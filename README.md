# Fund Transfer App (fundAPP)

**Fund Transfer App (fundAPP)** is a Flask-based web application designed for secure and easy fund transfers between users. This application intentionally includes vulnerabilities in its REST API to serve as a learning platform for cybersecurity professionals or beginners to test their penetration testing skills. It features a role-based system with full CRUD (Create, Read, Update, Delete) capabilities for admins, while regular users can transfer funds between accounts. The app also supports OTP handling via email for secure authentication, session management, and caching to optimize performance.

## Features
- **API Vulnerabilities**: Demonstrates vulnerabilities based on OWASP Top 10 (2021)
- **OpenAPI3 Specs & Postman Collection**: Predefined specifications for testing and interacting with the API
- **Swagger UI Integration**: Interact directly with the API via Swagger
- **Vulnerable REST API**: Designed for testing and learning cybersecurity skills
- **Role-Based Access Control**:
  - **Admin**: Perform CRUD operations on users and transactions
  - **User**: Transfer funds between accounts
- **Email-Based OTP (One-Time Password)**: Secure password reset functionality
- **Session & Caching**: Enhances performance and scalability
- **Admin Dashboard**: Full control over users, transactions, and application management
- **Fund Transfer Feature**: Easy and secure money transfers between users
- **Database Reset**: Admin-exclusive ability to reset the database

## Vulnerabilities (To be added)

## Prerequisites
- Python 3.x
- Flask 2.x or higher
- Virtual environment (recommended)

## Installation

Follow these steps to set up the application:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Aayushrajthala99/fundAPP.git
   cd fundAPP
   ```

2. **Create and activate a virtual environment** (recommended):
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment (Windows)
   venv\Scripts\activate

   # Activate virtual environment (macOS/Linux)
   source venv/bin/activate
   ```

3. **Install dependencies**:
   Install the required Python packages using the `requirements.txt` file.
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   - Create a `.env` file based on the `.env.example` template and fill in your configuration details.
   - Ensure sensitive values like `SECRET_KEY`, `JWT_SECRET_KEY`, and `MAIL_APP_KEY` are configured correctly.

   Below is the content of the `.env.example` file template:

   ```env
   # .env.example
   APP_PORT=5000
   SESSION_TYPE=filesystem
   SESSION_DIR=flask_session
   CACHE_TYPE=FileSystemCache
   CACHE_DIR=cache
   CACHE_DEFAULT_TIMEOUT=300
   CACHE_THRESHOLD=100
   PERMANENT_SESSION_LIFETIME=10

   MAIL_SERVER=smtp.example.com
   MAIL_PORT=587
   MAIL_EMAIL=your-email@example.com
   MAIL_USE_TLS=True
   MAIL_APP_KEY=your-mail-app-key

   SECRET_KEY=your-secret-key
   JWT_SECRET_KEY=your-jwt-secret-key

   DATABASE_URI=your-database-uri
   FUNDAPP_LOG_PATH=fundAPP.log
   DB_MIGRATIONS_FILE=database/migrations.sql
   ```

5. **Run the application**:
   Once the environment is set up and the `.env` file is configured, you can run the application:
   ```bash
   python app.py
   ```

6. **Access the application**:
   Open a browser and navigate to `http://127.0.0.1:5000` to access the application.

## Usage
The app provides two main roles:
- **Admin**: Manage users and transactions with full CRUD functionality.
- **User**: Transfer funds between accounts and view transaction history.

## Screenshots
- [Home](readme-images/home.png)
- [Login](readme-images/login.png)
- [Register](readme-images/register.png)
- [Add User](readme-images/add_user.png)
- [Transactions](readme-images/transactions.png)
- [Transfer Funds](readme-images/tranfser_funds.png)
- [Admin Dashboard](readme-images/admin.png)
- [Change Password](readme-images/change_password.png)
- [Report Bug](readme-images/report_bug.png)
- [Feedback](readme-images/feedback.png)

## Roadmap
Planned enhancements for the project:
1. **Dockerization**: Provide Docker support for easier and faster deployment.
2. **Responsive Design**: Improve the UI for mobile and tablet support.
3. **Documentation**: Improve the documentation & postman collection to list all the vulnerabilities.

## Contributing
Contributions are welcome! If you'd like to contribute, please follow these steps:
1. Fork the repository.
2. Create a new feature branch: `git checkout -b feature/my-feature`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature/my-feature`.
5. Open a pull request.

## License
This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for details.

## Authors
- **Aayush Rajthala** ([@Aayushrajthala99](https://github.com/Aayushrajthala99))

## Project Status
This project is currently **ongoing**, with new features and bug fixes being implemented regularly. I'm open to collaboration and contributions to improve the project.