# Spring Boot Authentication Backend

## Overview

This project provides a backend API service for user authentication and session management, implemented using Java and the Spring Boot framework. It offers functionalities including JWT (JSON Web Token) generation and validation, IP address binding for sessions, secure cookie handling, and CSRF protection using state tokens.

This implementation serves as a robust alternative or migration path from a similar system previously built with PHP.

## Features

* **JWT Authentication:** Securely generates and validates JWTs for stateless authentication.
* **IP-Based Session Management:** Associates authentication sessions with client IP addresses stored in the database.
* **Automatic Session Refresh:** Handles session continuation and token refresh based on cookie presence or active database sessions.
* **IP Address Change Handling:** Automatically updates sessions and issues new tokens if a user's IP address changes while possessing a valid token.
* **State Token CSRF Protection:** Implements a state token mechanism (`/initiate-auth` and `/auth-callback`) to prevent Cross-Site Request Forgery during authentication flows.
* **Secure Cookie Handling:** Sets HttpOnly, Secure, and SameSite=None cookies for storing authentication tokens.
* **RESTful API Endpoints:** Provides clear endpoints for initiating auth, checking status, verifying tokens, and handling callbacks.
* **Configuration Driven:** Key parameters like JWT secrets, database credentials, and timeouts are managed via `application.properties`.

## Technology Stack

* **Java:** Version 17 or later
* **Spring Boot:** Framework for building the application (v3.1.x or later recommended)
* **Spring Web:** For building RESTful APIs
* **Spring Data JPA:** For database interaction
* **Hibernate:** JPA implementation
* **MySQL:** Relational database for storing session and state information
* **JJWT (Java JWT):** Library for JWT creation and validation
* **Maven:** Dependency management and build tool
* **Lombok:** To reduce boilerplate code

## Prerequisites

Before running the application, ensure you have the following installed:

* **Java Development Kit (JDK):** Version 17 or higher.
* **Apache Maven:** For building the project.
* **MySQL Server:** A running instance of MySQL database.

## Configuration

1.  **Database Setup:**
    * Ensure your MySQL server is running.
    * Create a database named `clotheeo_savecontentbot` (or update the name in the configuration).
    * The application uses Hibernate's `ddl-auto=update` by default, which will attempt to create/update the necessary tables (`auth_sessions`, `auth_state`) on startup. **Important:** For production environments, it is strongly recommended to set `spring.jpa.hibernate.ddl-auto` to `validate` or `none` and manage schema changes manually using migration tools (like Flyway or Liquibase).

2.  **Application Properties:**
    * Modify the `src/main/resources/application.properties` file to match your environment:
        ```properties
        # Database Configuration
        spring.datasource.url=jdbc:mysql://localhost:3306/clotheeo_savecontentbot?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
        spring.datasource.username=YOUR_DB_USERNAME
        spring.datasource.password=YOUR_DB_PASSWORD

        # JWT Configuration
        # IMPORTANT: Use environment variables or a secure configuration server in production!
        jwt.secret=YOUR_SUPER_SECRET_AND_LONG_HEX_ENCODED_KEY_MIN_32_BYTES
        jwt.expiration.ms=43200000 # 12 hours
        jwt.cookie.name=auth_token

        # State Token Configuration
        state.token.expiration.seconds=600 # 10 minutes

        # Frontend Redirect URL (for /auth-callback)
        frontend.redirect.baseurl=http://localhost:3000 # Your frontend app URL
        ```
    * **Security Note:** Never commit sensitive information like `jwt.secret` or database passwords directly into your version control. Use environment variables, Spring Cloud Config, or other secure configuration management practices.

## Setup and Running

1.  **Clone the Repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Configure:** Update `application.properties` as described in the Configuration section.

3.  **Build the Project:**
    ```bash
    mvn clean package
    ```
    This command compiles the code, runs tests, and packages the application into an executable JAR file located in the `target/` directory (e.g., `auth-demo-0.0.1-SNAPSHOT.jar`).

4.  **Run the Application:**
    ```bash
    java -jar target/auth-demo-0.0.1-SNAPSHOT.jar
    ```
    The application will start, and the API will be available, typically at `http://localhost:8080`.

## API Endpoints Summary

The API endpoints are available under the base path `/api/auth`.

* `GET /initiate-auth`: Generates a state token to start an authentication flow.
* `GET /check-auth`: Checks the current authentication status using cookies or DB sessions. Sets/refreshes cookies as needed.
* `POST /verify-token`: Verifies a provided JWT against the current client IP. Requires `{ "token": "..." }` in the request body.
* `GET /auth-callback?state=...`: Handles the redirect after an external auth step, verifies the state token, sets the auth cookie, and redirects to the frontend.

*(For detailed request/response examples, please refer to separate API documentation or test using tools like Postman with the provided examples.)*

## Security Considerations

* **JWT Secret:** Keep your `jwt.secret` highly confidential and ensure it's sufficiently long and complex (at least 256 bits / 32 bytes for HS256). Use secure methods for managing secrets in production.
* **HTTPS:** Always run this application behind a reverse proxy (like Nginx or Apache) configured with HTTPS in production to protect data in transit, especially cookies and tokens. The `Secure` flag on cookies requires HTTPS.
* **CORS:** The default `WebConfig` allows all origins (`*`) for development ease. **In production, strictly configure `allowedOrigins`** in `WebConfig.java` to only allow requests from your specific frontend domain(s).
* **Input Validation:** While basic validation is present, ensure all external inputs are thoroughly validated to prevent injection attacks or unexpected behavior.
* **Rate Limiting:** Consider implementing rate limiting on authentication endpoints to mitigate brute-force attacks.
* **Database Security:** Secure your database with strong credentials and appropriate network access controls.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

*(Optional: Add more specific contribution guidelines if desired.)*

## License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). 

You are free to use, modify, and distribute this software under the terms of the Apache License 2.0. 
