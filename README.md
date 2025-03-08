# Secure-web-application

This project present an example secure web application using Flask and containerized with Docker.
Tech stack used:
 - Python
 - SQLAlchemy
 - Flask
 - Docker
 - Proxy with Nginx
 - SQLite

If one wish to run this application have to do two thing:
1. In project root directory add `.env` file with two specified secrets written like this in the beginning of the file:
SECRET_KEY=<your-secret>
OTP_SECRET_ENCRYPTION_PASSWORD=<your-secret>

2. In nginx/ssl directory add server certificate as file `server.crt` and server private key as file `server.key`. The key should be RSA 4096 bit. OpenSSL library might be helpful for that.