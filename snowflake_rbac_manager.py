import streamlit as st
from snowflake.snowpark import Session
import os
from typing import List, Dict
from titan.blueprint import Blueprint
from titan.resources import Grant, Role, Warehouse, Database, Schema

class SnowflakeRBACManager:
    def __init__(self):
        self.session = self._get_snowflake_connection()
        
    def _get_snowflake_connection(self):
        """Establish Snowflake connection using environment variables or Streamlit secrets"""
        try:
            connection_params = {
                "account": st.secrets["snowflake"]["account"],
                "user": st.secrets["snowflake"]["user"],
                "password": st.secrets["snowflake"]["password"],
                "role": "SECURITYADMIN",  # Best practice for RBAC management
            }
            return Session.builder.configs(connection_params).create()
        except Exception as e:
            st.error(f"Failed to connect to Snowflake: {str(e)}")
            return None

    def get_role_privileges(self, role_name: str) -> List[Dict]:
        """Fetch all privileges for a given role"""
        query = f"""
        SHOW GRANTS TO ROLE {role_name};
        """
        results = self.session(query).collect()
        return [dict(zip(['privilege', 'granted_on', 'object_name', 'granted_to', 'grantee_name'], row))
                for row in results]

    def create_functional_roles(self, base_role_name: str) -> Blueprint:
        """Create functional roles following Snowflake best practices"""
        roles = [
            Role(name=f"{base_role_name}_full"),  # Full access
            Role(name=f"{base_role_name}_read"),  # Read-only access
            Role(name=f"{base_role_name}_write"),  # Write access
        ]
        
        warehouse = Warehouse(
            name=f"{base_role_name}_wh",
            warehouse_size="x-small",
            auto_suspend=60,
        )
        
        grants = [
            Grant(priv="usage", to=roles[0], on=warehouse),  # Full access
            Grant(priv="usage", to=roles[1], on=warehouse),  # Read access
            Grant(priv="usage", to=roles[2], on=warehouse),  # Write access
        ]
        
        return Blueprint(resources=[*roles, warehouse, *grants])

def main():
    st.write("Loading application...")  # Debug message
    st.title("Snowflake RBAC Manager")
    
    # Test if basic Streamlit functionality works
    if st.button("Click me"):
        st.write("Button clicked!")
    
    rbac_manager = SnowflakeRBACManager()
    
    # Sidebar for main operations
    operation = st.sidebar.selectbox(
        "Select Operation",
        ["View Role Privileges", "Create New Role", "Manage Privileges"]
    )
    
    if operation == "View Role Privileges":
        st.header("Role Privileges")
        role_name = st.text_input("Enter Role Name").upper()
        
        if st.button("View Privileges"):
            if role_name:
                privileges = rbac_manager.get_role_privileges(role_name)
                st.dataframe(privileges)
            else:
                st.warning("Please enter a role name")
    
    elif operation == "Create New Role":
        st.header("Create New Role")
        base_role_name = st.text_input("Enter Base Role Name")
        
        if st.button("Create Functional Roles"):
            if base_role_name:
                try:
                    bp = rbac_manager.create_functional_roles(base_role_name)
                    plan = bp.plan(rbac_manager.connection)
                    
                    # Show the plan
                    st.subheader("Planned Changes")
                    st.code(str(plan))
                    
                    if st.button("Apply Changes"):
                        bp.apply(rbac_manager.connection, plan)
                        st.success("Roles created successfully!")
                except Exception as e:
                    st.error(f"Error creating roles: {str(e)}")
            else:
                st.warning("Please enter a base role name")
    
    elif operation == "Manage Privileges":
        st.header("Manage Privileges")
        
        col1, col2 = st.columns(2)
        
        with col1:
            action = st.selectbox("Action", ["Grant", "Revoke"])
            privilege = st.selectbox(
                "Privilege",
                ["USAGE", "SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES"]
            )
            
        with col2:
            object_type = st.selectbox(
                "Object Type",
                ["WAREHOUSE", "DATABASE", "SCHEMA", "TABLE"]
            )
            object_name = st.text_input("Object Name").upper()
            
        role_name = st.text_input("Role Name").upper()
        
        if st.button("Execute"):
            if all([privilege, object_type, object_name, role_name]):
                try:
                    role = Role(name=role_name)
                    grant = Grant(
                        priv=privilege.lower(),
                        to=role,
                        on=object_name  # This is simplified - you'd need to create proper object references
                    )
                    
                    bp = Blueprint(resources=[grant])
                    plan = bp.plan(rbac_manager.connection)
                    
                    st.subheader("Planned Changes")
                    st.code(str(plan))
                    
                    if st.button("Confirm Changes"):
                        bp.apply(rbac_manager.connection, plan)
                        st.success("Privileges updated successfully!")
                except Exception as e:
                    st.error(f"Error managing privileges: {str(e)}")
            else:
                st.warning("Please fill in all fields")

if __name__ == "__main__":
    main() 