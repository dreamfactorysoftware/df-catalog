import streamlit as st
import extra_streamlit_components as stx
import requests
import json
import secrets
import string
import time
from sqlalchemy import create_engine, Column, Integer, String, JSON, Boolean, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
import uuid
import datetime
import logging
import pandas as pd
import streamlit.components.v1 as components
import base64
from PIL import Image
import io
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "sqlite:///dreamfactory_access.db"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# Define RBAC options globally
rbac_options = ["read", "create", "update", "delete"]

# Define all models
class AppConfig(Base):
    __tablename__ = 'app_config'
    id = Column(Integer, primary_key=True)
    app_name = Column(String, default="Data Portal")
    primary_color = Column(String, default="#29B5E8")
    secondary_color = Column(String, default="#1B2937")
    accent_color = Column(String, default="#2D3B4A")
    logo_data = Column(String)
    favicon_data = Column(String)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    organization = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class AdminRole(Base):
    __tablename__ = 'admin_roles'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    admin_level = Column(String)  # 'super_admin' or 'admin'
    granted_by = Column(Integer, ForeignKey('users.id'), nullable=True)  # null for first admin
    granted_at = Column(DateTime, default=datetime.utcnow)

class AccessRequest(Base):
    __tablename__ = 'access_requests'
    id = Column(Integer, primary_key=True)
    request_id = Column(String, unique=True, nullable=False)
    details = Column(JSON, nullable=False)

class ApprovedRequest(Base):
    __tablename__ = 'approved_requests'
    id = Column(Integer, primary_key=True)
    request_id = Column(String, unique=True, nullable=False)
    details = Column(JSON, nullable=False)

class UserSession(Base):
    __tablename__ = 'user_sessions'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    session_id = Column(String, unique=True)
    role = Column(String)
    expiry = Column(Integer)  # Unix timestamp

# Create tables AFTER all models are defined but BEFORE any functions
Base.metadata.create_all(engine)

# Define session context manager
@contextmanager
def get_db_session():
    session = Session()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()

# Helper functions for DreamFactory API calls
@st.cache_data(ttl=600)
def df_api_call(endpoint, method="GET", data=None, headers=None):
    base_url = st.secrets["dreamfactory_url"].rstrip('/')
    if not base_url.startswith(('http://', 'https://')):
        base_url = f"https://{base_url}"
    
    # Add /api/v2 prefix to the URL
    url = f"{base_url}/api/v2/{endpoint.lstrip('/')}"
    
    default_headers = {
        "X-DreamFactory-API-Key": st.secrets["admin_api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    headers = {**default_headers, **(headers or {})}
    
    try:
        logger.info(f"Making {method} request to: {url}")
        logger.info(f"Headers: {headers}")
        if data:
            logger.info(f"Request data: {data}")
        
        response = requests.request(method, url, headers=headers, json=data)
        
        # Log response details
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {response.headers}")
        logger.info(f"Response content: {response.text[:500]}...")
        
        if response.status_code == 401:
            st.error("Authentication failed. Please check your API key.")
            return None
        
        if response.status_code == 400:
            error_msg = response.json().get('error', {}).get('message', response.text)
            st.error(f"Bad request: {error_msg}")
            return None
            
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API call failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response content: {e.response.text}")
        st.error(f"API call failed: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            st.error(f"Response content: {e.response.text}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response: {str(e)}")
        st.error("Failed to parse API response")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in df_api_call: {str(e)}")
        st.error(f"Unexpected error: {str(e)}")
        return None

def get_user_role(user_id):
    # Implement logic to get user role from DreamFactory
    pass

# Instead, initialize the cookie_manager directly
cookie_manager = stx.CookieManager()

# Authentication and session management
if "user" not in st.session_state:
    st.session_state.user = None

def login():
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")

    if submit_button:
        try:
            logger.info(f"Login attempt for username: {username}")
            user_data = verify_user(username, password)
            if user_data:
                st.session_state.user = user_data
                logger.info(f"Set session state user: {st.session_state.user}")
                st.success(f"Logged in successfully as {user_data['role']}!")
                logger.info(f"User {username} logged in successfully as {user_data['role']}")
                st.rerun()
            else:
                st.error("Invalid username or password")
                logger.warning(f"Failed login attempt for username: {username}")
        except Exception as e:
            error_msg = f"An error occurred during login: {str(e)}"
            st.error(error_msg)
            logger.error(error_msg, exc_info=True)

def logout():
    logger.info("Logout initiated")
    with get_db_session() as session:
        if st.session_state.user:
            user_session = session.query(UserSession).filter_by(username=st.session_state.user['username']).first()
            if user_session:
                session.delete(user_session)
                logger.info(f"Deleted session for user: {st.session_state.user['username']}")
            else:
                logger.warning(f"No session found for user: {st.session_state.user['username']}")
        else:
            logger.warning("No user in session state during logout")
    st.session_state.user = None
    logger.info("Logout completed, session cleared")
    st.rerun()

def check_session():
    user_session = cookie_manager.get(cookie="user_session")
    logger.info(f"Retrieved user_session from cookie: {user_session}")
    if user_session:
        try:
            user_data = json.loads(user_session)
            logger.info(f"Parsed user_data: {user_data}")
            with get_db_session() as session:
                db_session = session.query(UserSession).filter_by(username=user_data['username']).first()
                if db_session and db_session.expiry > int(time.time()):
                    st.session_state.user = user_data
                    logger.info(f"Set session state user: {st.session_state.user}")
                else:
                    logger.info("Session expired or not found in database")
                    cookie_manager.delete(cookie="user_session")
                    st.session_state.user = None
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            cookie_manager.delete(cookie="user_session")
            st.session_state.user = None
        except Exception as e:
            logger.error(f"Unexpected error in check_session: {str(e)}")
            cookie_manager.delete(cookie="user_session")
            st.session_state.user = None
    else:
        logger.info("No user_session found in cookie")
        st.session_state.user = None

def apply_custom_styling():
    """Apply custom styling to the app"""
    config = get_app_config()
    
    # Apply custom styling
    custom_css = f"""
        <style>
            /* Custom theme */
            :root {{
                --primary-color: {config['primary_color']};
                --secondary-color: {config['secondary_color']};
                --accent-color: {config['accent_color']};
            }}
            
            /* Streamlit elements */
            .stButton > button {{
                background-color: var(--primary-color);
                color: white;
            }}
            .stTextInput > div > div > input {{
                background-color: var(--secondary-color);
                color: white;
            }}
            .stSelectbox > div > div {{
                background-color: var(--secondary-color);
                color: white;
            }}
        </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)
    return config

# Main app
def main():
    apply_custom_styling()
    clear_cache()
    
    # Get current config for title
    config = get_app_config()
    show_title(config)
    
    # Check if this is first run
    if check_first_run():
        first_admin_setup()
        return

    # Show login/register form if not logged in
    if 'user' not in st.session_state or not st.session_state.user:
        show_auth_form()
        return
    
    # If user is logged in and is admin, show admin panel
    if st.session_state.user and st.session_state.user.get('is_admin'):
        admin_panel()
    else:
        # Show regular user interface
        user_panel()

def first_admin_setup():
    st.title("First Admin Setup")
    st.info("Welcome! Since this is the first run, you need to create a super admin account.")
    
    with st.form("first_admin_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        full_name = st.text_input("Full Name")
        organization = st.text_input("Organization")
        
        if st.form_submit_button("Create Super Admin"):
            if password != confirm_password:
                st.error("Passwords do not match!")
                return
                
            try:
                user_id = create_user(username, password, full_name, organization)  # Get user ID instead of user object
                create_admin(user_id, admin_level='super_admin')  # Pass the user ID
                st.success("Super admin account created successfully!")
                st.info("Please refresh the page to log in.")
            except Exception as e:
                st.error(f"Error creating admin account: {str(e)}")

def show_auth_form():
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.form_submit_button("Login"):
                user = verify_user(username, password)
                if user:
                    st.session_state.user = user
                    st.rerun()
                else:
                    st.error("Invalid username or password")
    
    with tab2:
        with st.form("register_form"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            full_name = st.text_input("Full Name")
            organization = st.text_input("Organization")
            
            if st.form_submit_button("Register"):
                if new_password != confirm_password:
                    st.error("Passwords do not match!")
                    return
                    
                try:
                    create_user(new_username, new_password, full_name, organization)
                    st.success("Account created successfully! You can now log in.")
                except Exception as e:
                    st.error(f"Error creating account: {str(e)}")

def admin_panel():
    st.header("Admin Panel")
    
    # Add tabs for different admin functions
    tab1, tab2, tab3, tab4 = st.tabs(["API Management", "User Management", "Admin Management", "Portal Configuration"])
    
    with tab1:
        manage_apis()

    with tab2:
        manage_users()

    with tab3:
        if st.session_state.user.get('admin_level') == 'super_admin':
            manage_admins()
        else:
            st.warning("Only super admins can manage other administrators.")

    with tab4:
        manage_portal_config()

def manage_portal_config():
    st.subheader("Portal Configuration")
    
    with get_db_session() as session:
        config = session.query(AppConfig).first()
        
        # App Name
        new_app_name = st.text_input("Application Name", value=config.app_name)
        
        # Color Configuration
        col1, col2, col3 = st.columns(3)
        with col1:
            new_primary_color = st.color_picker("Primary Color", value=config.primary_color)
        with col2:
            new_secondary_color = st.color_picker("Secondary Color", value=config.secondary_color)
        with col3:
            new_accent_color = st.color_picker("Accent Color", value=config.accent_color)
        
        # Logo Upload
        st.subheader("Logo Configuration")
        uploaded_logo = st.file_uploader("Upload Logo", type=['png', 'jpg', 'jpeg'])
        if uploaded_logo:
            preview_col, _ = st.columns([1, 2])
            with preview_col:
                st.image(uploaded_logo, caption="Logo Preview", width=200)

        # Favicon Upload
        st.subheader("Favicon Configuration")
        uploaded_favicon = st.file_uploader("Upload Favicon", type=['png', 'ico'], key="favicon_uploader")
        if uploaded_favicon:
            preview_col, _ = st.columns([1, 2])
            with preview_col:
                st.image(uploaded_favicon, caption="Favicon Preview", width=32)
        
        # Save Changes
        if st.button("Save Configuration"):
            updates = {
                'app_name': new_app_name,
                'primary_color': new_primary_color,
                'secondary_color': new_secondary_color,
                'accent_color': new_accent_color,
            }
            
            if uploaded_logo:
                logo_data = process_uploaded_image(uploaded_logo)
                if logo_data:
                    updates['logo_data'] = logo_data
            
            if uploaded_favicon:
                favicon_data = process_uploaded_image(uploaded_favicon, max_size=(32, 32))
                if favicon_data:
                    updates['favicon_data'] = favicon_data
            
            if update_app_config(updates):
                st.success("Configuration updated successfully!")
                st.rerun()
            else:
                st.error("Failed to update configuration")

def manage_apis():
    st.subheader("API Management")
    
    # Fetch all APIs
    try:
        services = df_api_call("system/service")
        if not services or 'resource' not in services:
            st.error("Failed to fetch APIs from DreamFactory")
            return

        # Custom CSS for API boxes
        st.markdown("""
            <style>
                .api-box {
                    background-color: #2D3B4A;
                    padding: 1rem;
                    border-radius: 4px;
                    margin-bottom: 1rem;
                    border: 1px solid #3D4B5A;
                }
                .api-box h4 {
                    color: #29B5E8;
                    margin-top: 0;
                }
                .api-status {
                    float: right;
                    padding: 0.2rem 0.5rem;
                    border-radius: 3px;
                    font-size: 0.8rem;
                }
                .api-status.active {
                    background-color: #4CAF50;
                    color: white;
                }
                .api-status.inactive {
                    background-color: #F44336;
                    color: white;
                }
                .api-type {
                    color: #888;
                    font-size: 0.9rem;
                }
                .api-description {
                    margin-top: 0.5rem;
                    font-size: 0.9rem;
                }
                .api-users {
                    margin-top: 0.5rem;
                    padding: 0.5rem;
                    background-color: #1B2937;
                    border-radius: 3px;
                }
                .api-user {
                    display: inline-block;
                    margin: 0.2rem;
                    padding: 0.2rem 0.5rem;
                    background-color: #29B5E8;
                    color: white;
                    border-radius: 3px;
                    font-size: 0.8rem;
                }
            </style>
        """, unsafe_allow_html=True)

        # Get all approved requests to map users to APIs
        with get_db_session() as session:
            approved_requests = session.query(ApprovedRequest).all()
            api_users = {}
            for approved in approved_requests:
                api_name = approved.details.get('api')
                if api_name:
                    if api_name not in api_users:
                        api_users[api_name] = []
                    username = approved.request_id.split('_')[0]  # Extract username from request_id
                    api_users[api_name].append(username)

        # Display API List in expandable section
        with st.expander("Available APIs", expanded=False):
            for service in services['resource']:
                status_class = "active" if service.get('is_active', False) else "inactive"
                status_text = "Active" if service.get('is_active', False) else "Inactive"
                
                # Get users with access to this API
                users_with_access = api_users.get(service['name'], [])
                users_html = ""
                if users_with_access:
                    users_html = '<div class="api-users">Users with access: ' + \
                               ''.join([f'<span class="api-user">{user}</span>' for user in users_with_access]) + \
                               '</div>'
                
                st.markdown(f"""
                    <div class="api-box">
                        <span class="api-status {status_class}">{status_text}</span>
                        <h4>{service['name']}</h4>
                        <div class="api-type">Type: {service['type']}</div>
                        <div class="api-description">{service.get('description', 'No description available')}</div>
                        {users_html}
                    </div>
                """, unsafe_allow_html=True)

        # Access Requests Section
        with st.expander("Pending Access Requests", expanded=False):
            with get_db_session() as session:
                pending_requests = session.query(AccessRequest).all()
                
                if not pending_requests:
                    st.info("No pending access requests")
                else:
                    for request in pending_requests:
                        st.markdown(f"""
                            <div class="api-box">
                                <h4>Request from {request.request_id}</h4>
                                <div class="api-type">API: {request.details.get('api', 'Unknown')}</div>
                                <div class="api-description">
                                    Endpoints: {', '.join(request.details.get('endpoints', []))}
                                    <br>
                                    Permissions: {', '.join(request.details.get('permissions', []))}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        
                        # Show approval/denial buttons directly
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("Approve", key=f"approve_{request.request_id}"):
                                try:
                                    # Create role name
                                    role_name = f"role_{request.request_id}"
                                    
                                    # Create role in DreamFactory
                                    role_data = create_role_data(role_name, request.details)
                                    role_response = df_api_call("system/role", method="POST", data=role_data)
                                    
                                    if role_response and 'resource' in role_response:
                                        # Get the role ID from the first resource item
                                        role_id = role_response['resource'][0]['id']
                                        
                                        # Create app in DreamFactory
                                        app_name = f"app_{request.request_id}"
                                        app_data = create_app_data(app_name, None, role_id)
                                        app_response = df_api_call("system/app", method="POST", data=app_data)
                                        
                                        if app_response and 'resource' in app_response:
                                            # Get the app ID from the response
                                            app_id = app_response['resource'][0]['id']
                                            
                                            # Fetch the app details to get the API key
                                            app_details = df_api_call(f"system/app/{app_id}")
                                            
                                            if app_details and 'api_key' in app_details:
                                                # Store approved request with DreamFactory's API key
                                                approved_details = request.details.copy()
                                                approved_details.update({
                                                    'role_name': role_name,
                                                    'app_name': app_name,
                                                    'api_key': app_details['api_key']
                                                })
                                                
                                                new_approved = ApprovedRequest(
                                                    request_id=request.request_id,  # Use original request_id
                                                    details=approved_details
                                                )
                                                session.add(new_approved)
                                                session.delete(request)
                                                session.commit()
                                                
                                                st.success("Request approved successfully!")
                                                st.rerun()
                                            else:
                                                st.error("Failed to fetch API key from DreamFactory")
                                        else:
                                            st.error("Failed to create app in DreamFactory")
                                    else:
                                        st.error("Failed to create role in DreamFactory")
                                except Exception as e:
                                    st.error(f"Error processing approval: {str(e)}")
                        
                        with col2:
                            if st.button("Deny", key=f"deny_{request.request_id}"):
                                session.delete(request)
                                session.commit()
                                st.success("Request denied")
                                st.rerun()
                        
                        # Add a divider between requests
                        st.markdown("---")

        # Approved Access Section
        with st.expander("Approved Access", expanded=False):
            with get_db_session() as session:
                approved_requests = session.query(ApprovedRequest).all()
                
                if not approved_requests:
                    st.info("No approved access requests")
                else:
                    for approved in approved_requests:
                        st.markdown(f"""
                            <div class="api-box">
                                <h4>Access for {approved.request_id}</h4>
                                <div class="api-type">API: {approved.details.get('api', 'Unknown')}</div>
                                <div class="api-description">
                                    Role: {approved.details.get('role_name', 'N/A')}
                                    <br>
                                    App: {approved.details.get('app_name', 'N/A')}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        
                        # Show details and revoke button in columns
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.code(json.dumps(approved.details, indent=2), language='json')
                        
                        with col2:
                            if st.button("Revoke Access", key=f"revoke_{approved.request_id}"):
                                try:
                                    # Delete role and app from DreamFactory
                                    df_api_call(f"system/role/{approved.details['role_name']}", method="DELETE")
                                    df_api_call(f"system/app/{approved.details['app_name']}", method="DELETE")
                                    
                                    # Delete from database
                                    session.delete(approved)
                                    session.commit()
                                    
                                    st.success("Access revoked successfully")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error revoking access: {str(e)}")
                        
                        st.markdown("---")

    except Exception as e:
        st.error(f"Error in API Management: {str(e)}")
        logger.error(f"API Management error: {str(e)}", exc_info=True)

def manage_users():
    st.subheader("User Management")
    
    with get_db_session() as session:
        users = session.query(User).all()
        
        # Create a DataFrame for better display
        user_data = []
        for user in users:
            admin_role = session.query(AdminRole).filter_by(user_id=user.id).first()
            user_data.append({
                'ID': user.id,
                'Username': user.username,
                'Full Name': user.full_name,
                'Organization': user.organization,
                'Role': admin_role.admin_level if admin_role else 'User',
                'Status': 'Active' if user.is_active else 'Inactive',
                'Created': user.created_at.strftime('%Y-%m-%d')
            })
        
        df = pd.DataFrame(user_data)
        st.dataframe(df)
        
        # User actions
        st.subheader("User Actions")
        col1, col2 = st.columns(2)
        
        with col1:
            user_to_modify = st.selectbox(
                "Select User",
                options=[user.username for user in users],
                key="user_modify"
            )
            
            selected_user = next((u for u in users if u.username == user_to_modify), None)
            if selected_user:
                current_status = selected_user.is_active
                new_status = st.checkbox("Active", value=current_status)
                
                if st.button("Update Status"):
                    selected_user.is_active = new_status
                    session.commit()
                    st.success(f"Updated status for {user_to_modify}")
                    st.rerun()

def manage_admins():
    st.subheader("Admin Management")
    
    with get_db_session() as session:
        # Get all admins
        admin_roles = session.query(AdminRole).all()
        admin_data = []
        
        for admin_role in admin_roles:
            user = session.query(User).filter_by(id=admin_role.user_id).first()
            granted_by_user = session.query(User).filter_by(id=admin_role.granted_by).first() if admin_role.granted_by else None
            
            admin_data.append({
                'Username': user.username,
                'Full Name': user.full_name,
                'Admin Level': admin_role.admin_level,
                'Granted By': granted_by_user.username if granted_by_user else 'System',
                'Granted At': admin_role.granted_at.strftime('%Y-%m-%d %H:%M')
            })
        
        # Display current admins
        st.write("Current Administrators")
        admin_df = pd.DataFrame(admin_data)
        st.dataframe(admin_df)
        
        # Add new admin
        st.subheader("Add New Administrator")
        
        # Get non-admin users
        non_admin_users = session.query(User).filter(
            ~User.id.in_(
                session.query(AdminRole.user_id)
            )
        ).all()
        
        if non_admin_users:
            col1, col2 = st.columns(2)
            
            with col1:
                new_admin_username = st.selectbox(
                    "Select User",
                    options=[user.username for user in non_admin_users]
                )
                
                admin_level = st.selectbox(
                    "Admin Level",
                    options=['admin', 'super_admin']
                )
                
                if st.button("Grant Admin Access"):
                    user_to_promote = next(u for u in non_admin_users if u.username == new_admin_username)
                    create_admin(
                        user_to_promote.id,
                        admin_level=admin_level,
                        granted_by=st.session_state.user['id']
                    )
                    st.success(f"Granted {admin_level} access to {new_admin_username}")
                    st.rerun()
        else:
            st.info("No eligible users to promote to admin.")
        
        # Revoke admin access
        st.subheader("Revoke Admin Access")
        
        revokable_admins = [
            admin for admin in admin_roles 
            if admin.admin_level != 'super_admin' or len(admin_roles) > 1
        ]
        
        if revokable_admins:
            admin_to_revoke = st.selectbox(
                "Select Admin",
                options=[
                    session.query(User).filter_by(id=admin.user_id).first().username 
                    for admin in revokable_admins
                ]
            )
            
            if st.button("Revoke Admin Access"):
                user_to_revoke = session.query(User).filter_by(username=admin_to_revoke).first()
                admin_role = session.query(AdminRole).filter_by(user_id=user_to_revoke.id).first()
                session.delete(admin_role)
                session.commit()
                st.success(f"Revoked admin access from {admin_to_revoke}")
                st.rerun()
        else:
            st.info("No admins available to revoke (must keep at least one super admin)")

# Helper functions for creating role and app data
def create_role_data(role_name, request_details):
    # Add timestamp to make role name unique
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_role_name = f"{role_name}_{timestamp}"
    
    # Create permission mapping
    permission_map = {
        "read": 1,      # GET
        "create": 2,    # POST
        "update": 4,    # PATCH/PUT
        "delete": 8     # DELETE
    }
    
    # Calculate verb mask by summing the values for each permission
    verb_mask = sum(permission_map[perm] for perm in request_details['permissions'])
    
    # Get service ID
    service_id = get_service_id(request_details['api'])
    
    # Create the service access array
    service_access = []
    for endpoint in request_details['endpoints']:
        service_access.append({
            "id": None,
            "verb_mask": verb_mask,
            "requestor_mask": 1,
            "component": "_table/*" if endpoint == '*' else f"_table/{endpoint}/*",  # Added /* to component path
            "service_id": service_id,
            "filters": [],
            "filter_op": "AND"
        })
    
    return {
        "resource": [{
            "id": 0,
            "name": unique_role_name,
            "description": unique_role_name,
            "is_active": True,
            "role_service_access_by_role_id": service_access,  # Changed from role_service_access
            "lookup_by_role_id": []  # Added lookup_by_role_id array
        }]
    }

def create_app_data(app_name, api_key, role_id):
    # Add timestamp to make app name unique
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_app_name = f"{app_name}_{timestamp}"
    
    return {
        "resource": [{
            "name": unique_app_name,
            "description": unique_app_name,
            "type": "0",  # Changed to string "0"
            "role_id": role_id,
            "is_active": True,
            "url": None,  # Changed from "*" to None
            "storage_service_id": None,
            "storage_container": None,
            "path": None  # Changed from "*" to None
        }]
    }

def get_service_id(api_name):
    services = df_api_call("system/service")
    if not services or 'resource' not in services:
        raise ValueError("Failed to fetch services from DreamFactory")
    
    for service in services['resource']:
        if service['name'] == api_name:
            return service['id']
    raise ValueError(f"Service {api_name} not found")

def user_panel():
    st.header("User Dashboard")
    
    # Define RBAC options globally
    rbac_options = ["read", "create", "update", "delete"]
    
    # Accessible APIs
    with st.expander("My Accessible APIs", expanded=True):
        st.subheader("APIs You Can Access")
        with get_db_session() as session:
            user_apis = session.query(ApprovedRequest).filter(
                ApprovedRequest.request_id.startswith(st.session_state.user['username'])
            ).all()
            if user_apis:
                for request in user_apis:
                    with st.container():
                        st.markdown(f"""
                            <div style="
                                background-color: #2D3B4A;
                                padding: 1rem;
                                border-radius: 4px;
                                margin-bottom: 1rem;
                                border: 1px solid #3D4B5A;
                            ">
                                <h4 style="color: #29B5E8; margin-top: 0;">{request.details['api']}</h4>
                            </div>
                        """, unsafe_allow_html=True)
                        
                        # Show API details in columns
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**API Key:**")
                            st.code(request.details.get('api_key', 'N/A'), language='text')
                        
                        with col2:
                            st.markdown("**Base URL:**")
                            base_url = f"{st.secrets['dreamfactory_url']}/api/v2/{request.details['api']}"
                            st.code(base_url, language='text')
                        
                        # Show endpoints and permissions
                        st.markdown("**Endpoints:**")
                        if '*' in request.details.get('endpoints', []):
                            st.info("You have access to all endpoints")
                        else:
                            for endpoint in request.details.get('endpoints', []):
                                st.code(f"{base_url}/_table/{endpoint}", language='text')
                        
                        st.markdown("**Permissions:**")
                        st.write(", ".join(request.details.get('permissions', [])))
                        
                        # Add a divider
                        st.markdown("---")
            else:
                st.info("You don't have access to any APIs yet.")
    
    # Data and API Access
    with st.expander("Request Access to APIs", expanded=False):
        try:
            services = df_api_call("system/service")
            if services and isinstance(services, dict) and 'resource' in services:
                # Filter out system APIs
                excluded_apis = ["api_docs", "system", "logs", "local_file", "db", "email", "user", "files"]
                available_apis = [
                    service['name'] for service in services['resource']
                    if service['name'] not in excluded_apis
                ]
                
                if not available_apis:
                    st.warning("No APIs available for request.")
                    return
                
                api_to_request = st.selectbox("Select API", available_apis)
                
                if api_to_request:
                    # Fetch schema for selected API
                    schema = df_api_call(f"{api_to_request}/_schema")
                    if schema and isinstance(schema, dict) and 'resource' in schema:
                        # Get available tables/endpoints
                        table_endpoints = ['*']  # Always include wildcard option
                        for resource in schema['resource']:
                            if isinstance(resource, dict) and 'name' in resource:
                                table_endpoints.append(resource['name'])
                        
                        selected_endpoints = st.multiselect(
                            "Select tables/endpoints to access",
                            options=table_endpoints
                        )
                        
                        # Show preview of selected endpoints
                        if selected_endpoints:
                            st.write("### Preview of Selected Endpoints")
                            for endpoint in selected_endpoints:
                                if endpoint != '*':  # Skip preview for wildcard selection
                                    st.write(f"#### {endpoint}")
                                    try:
                                        preview_data = df_api_call(f"{api_to_request}/_table/{endpoint}?limit=1")
                                        if preview_data and 'resource' in preview_data:
                                            st.json(preview_data['resource'][0])
                                        else:
                                            st.info(f"No preview data available for {endpoint}")
                                    except Exception as e:
                                        st.warning(f"Could not fetch preview for {endpoint}: {str(e)}")
                        
                        # Select permissions
                        selected_permissions = st.multiselect(
                            "Select permissions needed",
                            options=rbac_options
                        )
                        
                        # Submit button
                        if st.button("Submit Request"):
                            if not selected_endpoints:
                                st.warning("Please select at least one endpoint.")
                            elif not selected_permissions:
                                st.warning("Please select at least one permission.")
                            else:
                                request_id = f"{st.session_state.user['username']}_{api_to_request}"
                                request_details = {
                                    "api": api_to_request,
                                    "endpoints": selected_endpoints,
                                    "permissions": selected_permissions
                                }
                                
                                with get_db_session() as session:
                                    # Check if request already exists
                                    existing_request = session.query(AccessRequest).filter_by(
                                        request_id=request_id
                                    ).first()
                                    
                                    if existing_request:
                                        existing_request.details = request_details
                                        st.success(f"Updated access request for {api_to_request}")
                                    else:
                                        new_request = AccessRequest(
                                            request_id=request_id,
                                            details=request_details
                                        )
                                        session.add(new_request)
                                        st.success(f"Access request for {api_to_request} submitted!")
                                    
                                    session.commit()
                    else:
                        st.error("Failed to fetch API schema")
            else:
                st.error("Failed to fetch available APIs")
        except Exception as e:
            st.error(f"Error: {str(e)}")
    
    # API Documentation
    with st.expander("API Documentation", expanded=False):
        try:
            with get_db_session() as session:
                user_apis = session.query(ApprovedRequest).filter(
                    ApprovedRequest.request_id.startswith(st.session_state.user['username'])
                ).all()
                
                if not user_apis:
                    st.info("You don't have any APIs to document yet. Request access to APIs first.")
                    return

                api_choices = [req.details['api'] for req in user_apis if 'api' in req.details]
                if not api_choices:
                    st.warning("No valid APIs found.")
                    return
                
                selected_api = st.selectbox("Select API to view documentation", api_choices)
                
                selected_api_details = next(
                    (req.details for req in user_apis if req.details.get('api') == selected_api),
                    None
                )
                
                if selected_api_details:
                    # Fetch schema for the API
                    schema = df_api_call(f"{selected_api}/_schema")
                    if schema and 'resource' in schema:
                        # Generate OpenAPI spec
                        openapi_spec = {
                            "openapi": "3.0.0",
                            "info": {
                                "title": f"{selected_api} API Documentation",
                                "version": "1.0.0",
                                "description": f"API documentation for {selected_api}"
                            },
                            "servers": [
                                {
                                    "url": f"https://{st.secrets['dreamfactory_url']}/api/v2",
                                    "description": "DreamFactory API Server"
                                }
                            ],
                            "paths": {},
                            "components": {
                                "securitySchemes": {
                                    "ApiKey": {
                                        "type": "apiKey",
                                        "name": "X-DreamFactory-API-Key",
                                        "in": "header"
                                    }
                                },
                                "schemas": {}
                            },
                            "security": [{"ApiKey": []}]
                        }

                        # Build paths and schemas based on user's permissions
                        for resource in schema['resource']:
                            if isinstance(resource, dict) and 'name' in resource:
                                table_name = resource['name']
                                
                                # Check if user has access to this table
                                if ('*' in selected_api_details.get('endpoints', []) or 
                                    table_name in selected_api_details.get('endpoints', [])):
                                    
                                    # Add schema component
                                    openapi_spec["components"]["schemas"][table_name] = {
                                        "type": "object",
                                        "properties": {
                                            field['name']: {
                                                "type": field.get('type', 'string'),
                                                "description": field.get('description', ''),
                                            } for field in resource.get('field', [])
                                        }
                                    }

                                    # Add paths based on permissions
                                    base_path = f"/{selected_api}/_table/{table_name}"
                                    permissions = selected_api_details.get('permissions', [])
                                    
                                    openapi_spec["paths"][base_path] = {}
                                    
                                    # GET endpoint
                                    if "read" in permissions:
                                        openapi_spec["paths"][base_path]["get"] = {
                                            "summary": f"Get {table_name} records",
                                            "parameters": [
                                                {
                                                    "name": "limit",
                                                    "in": "query",
                                                    "description": "Number of records to return",
                                                    "schema": {"type": "integer", "default": 10}
                                                },
                                                {
                                                    "name": "offset",
                                                    "in": "query",
                                                    "description": "Number of records to skip",
                                                    "schema": {"type": "integer", "default": 0}
                                                },
                                                {
                                                    "name": "filter",
                                                    "in": "query",
                                                    "description": "Filter criteria",
                                                    "schema": {"type": "string"}
                                                }
                                            ],
                                            "responses": {
                                                "200": {
                                                    "description": "Successful response",
                                                    "content": {
                                                        "application/json": {
                                                            "schema": {
                                                                "type": "object",
                                                                "properties": {
                                                                    "resource": {
                                                                        "type": "array",
                                                                        "items": {
                                                                            "$ref": f"#/components/schemas/{table_name}"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    
                                    # POST endpoint
                                    if "create" in permissions:
                                        openapi_spec["paths"][base_path]["post"] = {
                                            "summary": f"Create new {table_name} record",
                                            "requestBody": {
                                                "required": True,
                                                "content": {
                                                    "application/json": {
                                                        "schema": {
                                                            "$ref": f"#/components/schemas/{table_name}"
                                                        }
                                                    }
                                                }
                                            },
                                            "responses": {
                                                "200": {
                                                    "description": "Record created successfully"
                                                }
                                            }
                                        }

                        # Create HTML with Swagger UI
                        swagger_html = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>API Documentation</title>
                            <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
                            <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
                            <style>
                                body {{
                                    background: #0e1117;
                                    margin: 0;
                                }}
                                .swagger-ui {{
                                    filter: invert(88%) hue-rotate(180deg);
                                }}
                            </style>
                        </head>
                        <body>
                            <div id="swagger-ui"></div>
                            <script>
                                window.onload = function() {{
                                    const ui = SwaggerUIBundle({{
                                        spec: {json.dumps(openapi_spec)},
                                        dom_id: '#swagger-ui',
                                        deepLinking: true,
                                        presets: [
                                            SwaggerUIBundle.presets.apis,
                                            SwaggerUIBundle.SwaggerUIStandalonePreset
                                        ],
                                        plugins: [
                                            SwaggerUIBundle.plugins.DownloadUrl
                                        ],
                                        requestInterceptor: (req) => {{
                                            req.headers['X-DreamFactory-API-Key'] = '{selected_api_details.get("api_key", "")}';
                                            return req;
                                        }}
                                    }});
                                }}
                            </script>
                        </body>
                        </html>
                        """
                        
                        # Display the Swagger UI
                        components.html(swagger_html, height=800, scrolling=True)
                    else:
                        st.error("Failed to fetch API schema")
                else:
                    st.error("Failed to find API details")
        except Exception as e:
            st.error(f"Error loading API documentation: {str(e)}")
            logger.error(f"Documentation error: {str(e)}", exc_info=True)

# Add these new helper functions
def check_role_exists(role_name):
    roles = df_api_call("system/role")
    if roles and 'resource' in roles:
        return any(role['name'] == role_name for role in roles['resource'])
    return False

def check_app_exists(app_name):
    apps = df_api_call("system/app")
    if apps and 'resource' in apps:
        return any(app['name'] == app_name for app in apps['resource'])
    return False

def check_api_exists(api_name):
    services = df_api_call("system/service")
    if services and 'resource' in services:
        return any(service['name'] == api_name for service in services['resource'])
    return False

def clear_cache():
    df_api_call.clear()

def get_app_config():
    """Get or create app configuration"""
    with get_db_session() as session:
        config = session.query(AppConfig).first()
        if not config:
            # Create default config
            config = AppConfig(
                app_name="Data Portal",
                primary_color="#29B5E8",
                secondary_color="#1B2937",
                accent_color="#2D3B4A"
            )
            session.add(config)
            session.commit()
            session.refresh(config)
        return {
            'app_name': config.app_name,
            'primary_color': config.primary_color,
            'secondary_color': config.secondary_color,
            'accent_color': config.accent_color,
            'logo_data': config.logo_data,
            'favicon_data': config.favicon_data
        }

def update_app_config(updates):
    try:
        with get_db_session() as session:
            config = session.query(AppConfig).first()
            if not config:
                config = AppConfig()
                session.add(config)
            
            # Log the updates being attempted
            logger.info(f"Attempting to update config with: {updates.keys()}")
            
            for key, value in updates.items():
                setattr(config, key, value)
                logger.info(f"Updated {key}")
            
            session.commit()
            session.refresh(config)
            logger.info("Configuration updated successfully")
            return True
    except Exception as e:
        error_msg = f"Error updating config: {str(e)}"
        logger.error(error_msg)
        st.error(error_msg)
        return False

def process_uploaded_image(uploaded_file, max_size=(800, 800)):
    if uploaded_file is None:
        return None
    
    try:
        # Read the file and reset pointer
        image_data = uploaded_file.getvalue()  # Use getvalue() instead of read()
        image = Image.open(io.BytesIO(image_data))
        
        # Resize if needed while maintaining aspect ratio
        image.thumbnail(max_size)
        
        # Convert to PNG and encode
        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        encoded_image = base64.b64encode(buffered.getvalue()).decode()
        
        # Log success
        logger.info(f"Successfully processed image: {uploaded_file.name}")
        return encoded_image
    except Exception as e:
        error_msg = f"Error processing image {uploaded_file.name}: {str(e)}"
        logger.error(error_msg)
        st.error(error_msg)
        return None

def adjust_color_brightness(color_hex, brightness_offset):
    # Convert hex to RGB
    color = color_hex.lstrip('#')
    rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
    
    # Adjust brightness
    new_rgb = tuple(
        max(0, min(255, value + brightness_offset))
        for value in rgb
    )
    
    # Convert back to hex
    return '#{:02x}{:02x}{:02x}'.format(*new_rgb)

def check_first_run():
    """Check if this is first run (no admins exist)"""
    with get_db_session() as session:
        return session.query(AdminRole).first() is None

def create_user(username, password, full_name, organization):
    """Create a new user"""
    with get_db_session() as session:
        if session.query(User).filter_by(username=username).first():
            raise ValueError("Username already exists")
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            full_name=full_name,
            organization=organization
        )
        session.add(user)
        session.commit()
        session.refresh(user)  # Refresh the user object
        return user.id  # Return just the ID instead of the user object

def create_admin(user_id, admin_level='admin', granted_by=None):
    """Create a new admin role for a user"""
    with get_db_session() as session:
        admin = AdminRole(
            user_id=user_id,
            admin_level=admin_level,
            granted_by=granted_by
        )
        session.add(admin)
        session.commit()
        return admin

def verify_user(username, password):
    """Verify user credentials"""
    with get_db_session() as session:
        user = session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            # Check if user is an admin
            admin_role = session.query(AdminRole).filter_by(user_id=user.id).first()
            return {
                'id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'is_admin': bool(admin_role),
                'admin_level': admin_role.admin_level if admin_role else None
            }
        return None

def show_title(config):
    # Create container for header with logout button
    header_cols = st.columns([0.5, 2.5, 1])
    
    # Style the container
    st.markdown("""
        <style>
            [data-testid="stHorizontalBlock"] {
                background-color: #2D3B4A;
                padding: 1.5rem;
                border-radius: 4px;
                margin-bottom: 2rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.3);
                border: 1px solid #3D4B5A;
                align-items: center;
            }
            [data-testid="column"] img {
                max-height: 80px !important;
                width: auto !important;
                display: block;
            }
            .logout-btn {
                float: right;
                padding: 0.5rem 1rem;
                background-color: transparent;
                border: 1px solid #29B5E8;
                color: #29B5E8;
                border-radius: 4px;
                cursor: pointer;
            }
            .logout-btn:hover {
                background-color: #29B5E8;
                color: white;
            }
        </style>
    """, unsafe_allow_html=True)
    
    # Show logo in first column if it exists
    if config.get('logo_data'):
        header_cols[0].image(
            f"data:image/png;base64,{config['logo_data']}", 
            use_column_width=True
        )
    
    # Show title and subtitle in middle column
    header_cols[1].markdown(f"""
        # {config['app_name']}
        <p style="color: #29B5E8; margin-top: 0.5rem; font-size: 1.1rem;">
            Secure Access Management for Data Products
        </p>
    """, unsafe_allow_html=True)
    
    # Show logout button if user is logged in
    if st.session_state.get('user'):
        if header_cols[2].button("Logout", key="logout_button"):
            logout()

# DreamFactory API Configuration
DREAMFACTORY_URL = st.secrets["dreamfactory_url"]
ADMIN_API_KEY = st.secrets["admin_api_key"]

if __name__ == "__main__":
    main()
