import streamlit as st
from snowflake.snowpark import Session
import os
from typing import List, Dict
from titan.blueprint import Blueprint
from titan.resources import Grant, Role, Warehouse, Database, Schema
import pandas as pd

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
            session = Session.builder.configs(connection_params).create()
            return session
        except Exception as e:
            st.error(f"Failed to connect to Snowflake: {str(e)}")
            return None

    def get_role_privileges(self, role_name: str) -> List[Dict]:
        """Fetch all privileges for a given role"""
        query = f"""
        SHOW GRANTS TO ROLE {role_name};
        """
        results = self.session.sql(query).collect()
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

    def compare_privileges(self, principal1: str, principal2: str, principal_type: str = "ROLE") -> dict:
        """Compare privileges between two roles or users"""
        if principal_type == "ROLE":
            query1 = f"SHOW GRANTS TO ROLE {principal1}"
            query2 = f"SHOW GRANTS TO ROLE {principal2}"
        else:  # USER
            query1 = f"SHOW GRANTS TO USER {principal1}"
            query2 = f"SHOW GRANTS TO USER {principal2}"
        
        results1 = self.session.sql(query1).collect()
        results2 = self.session.sql(query2).collect()
        
        # Convert results to sets of privileges for comparison
        privileges1 = {(row['privilege'], row['granted_on'], row['name']) for row in results1}
        privileges2 = {(row['privilege'], row['granted_on'], row['name']) for row in results2}
        
        return {
            'unique_to_first': privileges1 - privileges2,
            'unique_to_second': privileges2 - privileges1,
            'common': privileges1 & privileges2
        }

def main():
    st.write("Loading application...")  # Debug message
    st.title("Snowflake RBAC Manager")
    
    
    rbac_manager = SnowflakeRBACManager()
    
    # Sidebar for main operations
    operation = st.sidebar.selectbox(
        "Select Operation",
        ["View Role Privileges", "Create New Role", "Manage Privileges", "Compare Privileges"]
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
    
    elif operation == "Compare Privileges":
        st.header("Compare Privileges")
        
        principal_type = st.radio("Select Principal Type", ["ROLE", "USER"])
        
        col1, col2 = st.columns(2)
        with col1:
            principal1 = st.text_input(f"First {principal_type}").upper()
        with col2:
            principal2 = st.text_input(f"Second {principal_type}").upper()
            
        if st.button("Compare"):
            if principal1 and principal2:
                try:
                    comparison = rbac_manager.compare_privileges(principal1, principal2, principal_type)
                    
                    # Display results in tabs
                    tab1, tab2, tab3 = st.tabs(["Unique to First", "Unique to Second", "Common Privileges"])
                    
                    with tab1:
                        st.subheader(f"Privileges unique to {principal1}")
                        if comparison['unique_to_first']:
                            df1 = pd.DataFrame(comparison['unique_to_first'], 
                                             columns=['Privilege', 'Granted On', 'Object Name'])
                            st.dataframe(df1)
                        else:
                            st.info(f"No unique privileges for {principal1}")
                    
                    with tab2:
                        st.subheader(f"Privileges unique to {principal2}")
                        if comparison['unique_to_second']:
                            df2 = pd.DataFrame(comparison['unique_to_second'], 
                                             columns=['Privilege', 'Granted On', 'Object Name'])
                            st.dataframe(df2)
                        else:
                            st.info(f"No unique privileges for {principal2}")
                    
                    with tab3:
                        st.subheader("Common Privileges")
                        if comparison['common']:
                            df3 = pd.DataFrame(comparison['common'], 
                                             columns=['Privilege', 'Granted On', 'Object Name'])
                            st.dataframe(df3)
                        else:
                            st.info("No common privileges found")
                            
                except Exception as e:
                    st.error(f"Error comparing privileges: {str(e)}")
            else:
                st.warning(f"Please enter both {principal_type}s to compare")

if __name__ == "__main__":
    main() 