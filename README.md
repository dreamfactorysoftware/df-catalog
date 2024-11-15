# DreamFactory Access Portal

A Streamlit-based web application for managing access to DreamFactory APIs. This portal allows administrators to manage API access requests and users to request and view their API access.

## Features

- User registration and authentication
- API access request system
- Admin approval workflow
- Automatic role and API key provisioning
- Interactive API documentation with Swagger UI
- Portal customization options

## Prerequisites

- Python 3.7+
- DreamFactory instance with admin access
- SQLite (included with Python)

## Installation

1. Clone the repository:
```
git clone https://github.com/dreamfactorysoftware/df-streamlit.git
cd df-streamlit
```
2. Install required packages:
```
pip install -r requirements.txt
```

3. Create a `.streamlit/secrets.toml` file and add your DreamFactory URL and admin API key:
```
dreamfactory_url = "your_dreamfactory_instance_url"
admin_api_key = "your_dreamfactory_admin_api_key"
```

4. Run the application:
```
streamlit run streamlit_app.py
```

## Initial Setup

1. On first run, you'll be prompted to create a super admin account
2. Log in with the created super admin credentials
3. Use the admin panel to:
   - Configure portal appearance
   - Manage users and admins
   - Handle API access requests

## Usage

### For Administrators
- Approve or deny API access requests
- Manage users and their permissions
- Configure portal appearance
- Monitor API usage
- View users with access to each API
- Revoke access when needed

### For Users
- Request access to available APIs
- View granted API access details
- Access interactive API documentation
- Test API endpoints directly from the portal
- View their API keys and endpoints
- Preview data before requesting access

## DreamFactory Configuration

1. Obtain your DreamFactory instance URL (without http:// or https://)

2. Get your admin API key:
   - Log into DreamFactory admin console
   - Go to System > Roles > Admin
   - Copy the API Key

3. Configure services in DreamFactory:
   - Set up your database services
   - Configure file storage services
   - Set appropriate security settings

## Security Notes

- Store your `secrets.toml` securely and never commit it to version control
- Use strong passwords for admin accounts
- Regularly review API access permissions
- Monitor the access logs in DreamFactory
- Revoke access for inactive users
- Keep your DreamFactory instance updated

## Troubleshooting

Common issues and solutions:

1. Connection Issues:
   - Verify DreamFactory URL is correct (no http:// or https://)
   - Check admin API key is valid
   - Ensure DreamFactory instance is accessible

2. Access Problems:
   - Verify user permissions
   - Check role configurations
   - Review API key status

3. Database Issues:
   - Delete `dreamfactory_access.db` to reset the application
   - Restart the application to recreate tables

4. API Access Issues:
   - Ensure services are properly configured in DreamFactory
   - Check service permissions in DreamFactory
   - Verify API keys are active

## Development

To contribute to the development:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Guidelines:
- Follow Python PEP 8 style guide
- Add tests for new features
- Update documentation as needed
- Keep commits atomic and well-described

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Support

- For portal issues: Create an issue in the GitHub repository
- For DreamFactory questions: Visit [DreamFactory Forums](https://community.dreamfactory.com/)
- For security concerns: Contact security@dreamfactory.com

## Acknowledgments

- DreamFactory team and community
- Streamlit framework developers
- All contributors to this project

## Docker Installation

You can run the DreamFactory Access Portal using Docker:

### Option 1: Using Docker Compose (Recommended)

1. Create a `.streamlit/secrets.toml` file with your DreamFactory credentials:
```toml
dreamfactory_url = "your_dreamfactory_instance_url"
admin_api_key = "your_dreamfactory_admin_api_key"
```

2. Run with Docker Compose:
```bash
docker-compose up --build
```

3. Access the portal at `http://localhost:8501`

### Option 2: Using Docker Directly

1. Build the Docker image:
```bash
docker build -t dreamfactory-portal .
```

2. Run the container:
```bash
docker run -p 8501:8501 -v ~/.streamlit:/app/.streamlit dreamfactory-portal
```

### Docker Configuration Notes

- The application runs on port 8501 by default
- The container uses a non-root user for security
- The SQLite database persists in the container
- Secrets are mounted from your local `.streamlit` directory
- The container automatically pulls the latest code from GitHub during build

### Troubleshooting Docker Setup

1. Permission Issues:
   - Ensure your `.streamlit` directory has proper permissions
   - Check that secrets.toml is readable by the container

2. Port Conflicts:
   - If port 8501 is in use, modify the port mapping in docker-compose.yml
   - Example: `"8502:8501"` to use port 8502 on the host

3. Container Access:
   - Use `docker logs dreamfactory-portal` to view application logs
   - Use `docker exec -it dreamfactory-portal bash` to access the container shell

4. Volume Mounts:
   - Ensure your ~/.streamlit directory exists
   - Check that secrets.toml is properly mounted
