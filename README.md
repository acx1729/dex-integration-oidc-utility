## **1. How to Add Connectors**

### a. **Add General OIDC Connector**

To add a general OIDC connector, you will provide the required `issuer`, `client_id`, and `client_secret`:

```bash
curl -X POST http://localhost:8080/create/oidc \
     -H "Content-Type: application/json" \
     -d '{
           "issuer": "https://example.com",
           "client_id": "your-client-id",
           "client_secret": "your-client-secret"
         }'
```

### b. **Add EntraID OIDC Connector**

To add an EntraID OIDC connector, you will need to specify the `tenant_id`, along with `client_id` and `client_secret`:

```bash
curl -X POST http://localhost:8080/create/oidc/entraid \
     -H "Content-Type: application/json" \
     -d '{
           "tenant_id": "4725ad3d-5ab0-4f42-8a4a-fdee5ef586c5",
           "client_id": "your-client-id",
           "client_secret": "your-client-secret"
         }'
```

### c. **Add Google Workspace OIDC Connector**

To add a Google Workspace OIDC connector, you only need to provide the `client_id` and `client_secret`. The `issuer` will be set to `"https://accounts.google.com"` by default:

```bash
curl -X POST http://localhost:8080/create/oidc/google-workspace \
     -H "Content-Type: application/json" \
     -d '{
           "client_id": "your-client-id",
           "client_secret": "your-client-secret"
         }'
```

## **2. How to Delete a Connector**

To delete a connector, you will use its `connector_id`. 

### Example of Deleting a General OIDC Connector

Assuming you have created a connector with ID `default-oidc`, execute the following command to delete it:

```bash
curl -X DELETE http://localhost:8080/delete/default-oidc
```

### Example of Deleting an EntraID OIDC Connector

If the EntraID OIDC connector has ID `entraid-oidc`, use the following command:

```bash
curl -X DELETE http://localhost:8080/delete/entraid-oidc
```

### Example of Deleting a Google Workspace OIDC Connector

For the Google Workspace OIDC connector with ID `google-workspace-oidc`, execute:

```bash
curl -X DELETE http://localhost:8080/delete/google-workspace-oidc
```

## **3. How to List Connectors**

### a. **List All Connectors**

To list all connectors, simply send a GET request to the `/list` endpoint:

```bash
curl -X GET http://localhost:8080/list
```

### b. **List Connectors by Type (OIDC)**

If you want to filter the list to only show OIDC connectors, use:

```bash
curl -X GET http://localhost:8080/list/oidc
```

---

## **Summary**

In summary, the following `curl` commands can be used to interact with the OIDC connectors API:

### To Create Connectors:
- **General OIDC:** 
  ```bash
  curl -X POST http://localhost:8080/create/oidc ...
  ```
  
- **EntraID OIDC:** 
  ```bash
  curl -X POST http://localhost:8080/create/oidc/entraid ...
  ```

- **Google Workspace OIDC:** 
  ```bash
  curl -X POST http://localhost:8080/create/oidc/google-workspace ...
  ```

### To Delete Connectors:
- **General OIDC:** 
  ```bash
  curl -X DELETE http://localhost:8080/delete/default-oidc
  ```

- **EntraID OIDC:** 
  ```bash
  curl -X DELETE http://localhost:8080/delete/entraid-oidc
  ```

- **Google Workspace OIDC:** 
  ```bash
  curl -X DELETE http://localhost:8080/delete/google-workspace-oidc
  ```

### To List Connectors:
- **List All Connectors:** 
  ```bash
  curl -X GET http://localhost:8080/list
  ```

- **List OIDC Connectors Only:** 
  ```bash
  curl -X GET http://localhost:8080/list/oidc
  ```

Make sure to replace placeholders like `your-client-id` and `your-client-secret` with actual values appropriate for your setup.