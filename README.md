# Overview

This application provides a RESTful API for managing OIDC (OpenID Connect) connectors with Dex, an open-source OIDC provider. It serves as a backend service that allows users to create, update, delete, and list OIDC connectors over HTTP.

## Key Features

1. **Connector Types**:
    - Supports multiple types of OIDC connectors:
        - **General OIDC Connector**: Provides standard OIDC functionality with customizable issuer.
        - **EntraID OIDC Connector**: Integrates with Microsoft Entra (Azure AD) and fetches the issuer dynamically based on the specified tenant ID.
        - **Google Workspace OIDC Connector**: Facilitates OIDC authentication for Google Workspace applications.

2. **Connector Management**:
    - **Create**: Add new connectors with required parameters such as client ID and secret.
    - **Update**: Modify existing connectors while retaining their identities.
    - **Delete**: Remove connectors by their IDs.
    - **List**: Retrieve all configured connectors or filter by type.

3. **Dynamic Issuer Fetching**:
    - The EntraID connector automatically fetches the issuer URL based on the tenant ID.

4. **Validation**:
    - Ensures that all required fields are present and formatted correctly.

5. **Logging**:
    - Uses Logrus for detailed logging, aiding in monitoring and debugging.

## Usage Examples

### 1. How to Add Connectors

#### a. Add General OIDC Connector

```bash
curl -X POST http://localhost:8080/create/oidc \
     -H "Content-Type: application/json" \
     -d '{
           "issuer": "https://example.com",
           "client_id": "your-client-id",
           "client_secret": "your-client-secret"
         }'
```

#### b. Add EntraID OIDC Connector

```bash
curl -X POST http://localhost:8080/create/oidc/entraid \
     -H "Content-Type: application/json" \
     -d '{
           "tenant_id": "4725ad3d-5ab0-4f42-8a4a-fdee5ef586c5",
           "client_id": "your-client-id",
           "client_secret": "your-client-secret"
         }'
```

#### c. Add Google Workspace OIDC Connector

```bash
curl -X POST http://localhost:8080/create/oidc/google-workspace \
     -H "Content-Type: application/json" \
     -d '{
           "client_id": "your-client-id",
           "client_secret": "your-client-secret"
         }'
```

### 2. How to Delete a Connector

- **Delete a General OIDC Connector:**
  ```bash
  curl -X DELETE http://localhost:8080/delete/default-oidc
  ```

- **Delete an EntraID OIDC Connector:**
  ```bash
  curl -X DELETE http://localhost:8080/delete/entraid-oidc
  ```

- **Delete a Google Workspace OIDC Connector:**
  ```bash
  curl -X DELETE http://localhost:8080/delete/google-workspace-oidc
  ```

### 3. How to List Connectors

#### a. List All Connectors

```bash
curl -X GET http://localhost:8080/list
```

#### b. List Connectors by Type (OIDC)

```bash
curl -X GET http://localhost:8080/list/oidc
```

## Conclusion

This OIDC connector management application simplifies integration with various identity providers using OIDC. It supports dynamic issuer retrieval and comprehensive validation, making the setup process straightforward and enhancing the reliability of authentication services. Whether for generic OIDC applications or specific implementations like Google Workspace or EntraID, this application offers flexibility and functionality critical to modern identity management solutions.

## Summary of Commands

- **To Create Connectors:**
  - General OIDC:
    ```bash
    curl -X POST http://localhost:8080/create/oidc ...
    ```
  - EntraID OIDC:
    ```bash
    curl -X POST http://localhost:8080/create/oidc/entraid ...
    ```
  - Google Workspace OIDC:
    ```bash
    curl -X POST http://localhost:8080/create/oidc/google-workspace ...
    ```

- **To Delete Connectors:**
  - General OIDC:
    ```bash
    curl -X DELETE http://localhost:8080/delete/default-oidc
    ```
  - EntraID OIDC:
    ```bash
    curl -X DELETE http://localhost:8080/delete/entraid-oidc
    ```
  - Google Workspace OIDC:
    ```bash
    curl -X DELETE http://localhost:8080/delete/google-workspace-oidc
    ```

- **To List Connectors:**
  - List All Connectors:
    ```bash
    curl -X GET http://localhost:8080/list
    ```
  - List OIDC Connectors Only:
    ```bash
    curl -X GET http://localhost:8080/list/oidc
    ```

Make sure to replace placeholders like `your-client-id` and `your-client-secret` with actual values appropriate for your setup.
```