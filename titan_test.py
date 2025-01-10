import os
import snowflake.connector

from titan.blueprint import Blueprint, print_plan
from titan.resources import Grant, Role, Warehouse

role = Role(name="transformer")


roles = ['analyst', 'engineer', 'admin']
def roles_rbac(roles -> list):
    for role in roles:
        warehouse = Warehouse(
            name=f"{role}_wh",
            warehouse_size="x-small",
            auto_suspend=60,
        )

        usage_grant = Grant(priv="usage", to=role, on=warehouse)

# Titan compares your config to a Snowflake account. Create a Snowflake 
# connection to allow Titan to connect to your account.

connection_params = {
    "account": os.environ["SNOWFLAKE_ACCOUNT"],
    "user": os.environ["SNOWFLAKE_USER"],
    "password": os.environ["SNOWFLAKE_PASSWORD"],
    "role": "SYSADMIN",
}
session = snowflake.connector.connect(**connection_params)

bp = Blueprint(resources=[
    role,
    warehouse,
    usage_grant,
])

# Blueprint works like Terraform. Calling plan(...) will compare your config
# to the state of your Snowflake account and return a list of changes.

plan = bp.plan(session)

bp.apply(session, plan)