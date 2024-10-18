package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	dexapi "github.com/dexidp/dex/api/v2"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// OIDCConfig represents the configuration required for an OIDC connector.
type OIDCConfig struct {
	Issuer       string `json:"issuer,omitempty"`
	TenantID     string `json:"tenantID,omitempty"` // Added TenantID for entraid sub-type
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

// CreateConnectorRequest represents the expected payload for creating or updating a connector.
type CreateConnectorRequest struct {
	ConnectorType    string `json:"connector_type" validate:"required,oneof=oidc"`                                  // 'oidc' is supported for now
	ConnectorSubType string `json:"connector_sub_type" validate:"omitempty,oneof=general google-workspace entraid"` // Optional sub-type
	Issuer           string `json:"issuer,omitempty" validate:"omitempty,url"`
	TenantID         string `json:"tenant_id,omitempty" validate:"omitempty,uuid"`
	ClientID         string `json:"client_id" validate:"required"`
	ClientSecret     string `json:"client_secret" validate:"required"`
	ID               string `json:"id,omitempty"`   // Optional
	Name             string `json:"name,omitempty"` // Optional
}

// DexClient wraps the Dex gRPC client and manages the connection.
type DexClient struct {
	client   dexapi.DexClient
	conn     *grpc.ClientConn
	logger   *logrus.Logger
	validate *validator.Validate
	restrict bool
}

// ConnectorCreator is a function type for creating connectors based on type.
type ConnectorCreator func(dc *DexClient, params map[string]string) (*dexapi.CreateConnectorResp, error)

// connectorCreators maps connector types to their respective creator functions.
var connectorCreators = map[string]ConnectorCreator{
	"oidc": (*DexClient).CreateOIDCConnector,
	// Future connector types can be added here, e.g., "saml": (*DexClient).CreateSAMLConnector
}

// SupportedConnectors holds the supported connector types and their sub-types.
var SupportedConnectors = map[string][]string{
	"oidc": {"general", "google-workspace", "entraid"},
	// Add more connector types and their sub-types here as needed.
}

// NewDexClient initializes a new DexClient with a connection to the Dex gRPC server.
// Supports both secure (TLS) and insecure (HTTP) connections based on provided certificates.
func NewDexClient(hostAndPort, caPath, clientCrt, clientKey string, logger *logrus.Logger, restrict bool) (*DexClient, error) {
	var opts []grpc.DialOption

	if caPath != "" && clientCrt != "" && clientKey != "" {
		// Setup TLS credentials
		cPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			logger.Errorf("Invalid CA crt file: %s", caPath)
			return nil, fmt.Errorf("invalid CA crt file: %w", err)
		}
		if !cPool.AppendCertsFromPEM(caCert) {
			logger.Errorf("Failed to parse CA crt")
			return nil, fmt.Errorf("failed to parse CA crt")
		}

		clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
		if err != nil {
			logger.Errorf("Invalid client crt/key file: %s, %s", clientCrt, clientKey)
			return nil, fmt.Errorf("invalid client crt/key file: %w", err)
		}

		clientTLSConfig := &tls.Config{
			RootCAs:      cPool,
			Certificates: []tls.Certificate{clientCert},
		}
		creds := credentials.NewTLS(clientTLSConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
		logger.Info("Configured gRPC client with TLS")
	} else {
		// Use insecure connection
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logger.Info("Configured gRPC client with insecure connection")
	}

	// Set up blocking dial with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts = append(opts, grpc.WithBlock())

	conn, err := grpc.DialContext(ctx, hostAndPort, opts...)
	if err != nil {
		logger.Errorf("Failed to connect to Dex gRPC server: %v", err)
		return nil, fmt.Errorf("failed to connect to Dex gRPC server: %w", err)
	}

	client := dexapi.NewDexClient(conn)
	logger.Infof("Successfully connected to Dex gRPC server at %s", hostAndPort)

	// Initialize the validator
	validate := validator.New()

	return &DexClient{
		client:   client,
		conn:     conn,
		logger:   logger,
		validate: validate,
		restrict: restrict,
	}, nil
}

// Close gracefully closes the gRPC connection.
func (dc *DexClient) Close() error {
	err := dc.conn.Close()
	if err != nil {
		dc.logger.Errorf("Error closing Dex gRPC connection: %v", err)
		return err
	}
	dc.logger.Info("Dex gRPC connection closed successfully")
	return nil
}

// CreateOIDCConnector creates a new OIDC connector in Dex based on connector type and parameters.
func (dc *DexClient) CreateOIDCConnector(params map[string]string) (*dexapi.CreateConnectorResp, error) {
	connectorSubType := strings.ToLower(params["ConnectorSubType"])

	var oidcConfig OIDCConfig
	var connectorID, connectorName string

	switch connectorSubType {
	case "general":
		// Required: issuer, clientID, clientSecret
		oidcConfig = OIDCConfig{
			Issuer:       params["Issuer"],
			ClientID:     params["ClientID"],
			ClientSecret: params["ClientSecret"],
		}
		connectorID = params["id"]
		connectorName = params["name"]

		if connectorID == "" {
			connectorID = "default-oidc"
		}
		if connectorName == "" {
			connectorName = "OIDC SSO"
		}

	case "entraid":
		// Required: tenantID, clientID, clientSecret
		oidcConfig = OIDCConfig{
			TenantID:     params["TenantID"],
			ClientID:     params["ClientID"],
			ClientSecret: params["ClientSecret"],
		}
		connectorID = params["id"]
		connectorName = params["name"]

		if connectorID == "" {
			connectorID = "entraid-oidc"
		}
		if connectorName == "" {
			connectorName = "Microsoft AzureAD SSO"
		}

	case "google-workspace":
		// Required: clientID, clientSecret
		oidcConfig = OIDCConfig{
			ClientID:     params["ClientID"],
			ClientSecret: params["ClientSecret"],
		}
		connectorID = params["id"]
		connectorName = params["name"]

		if connectorID == "" {
			connectorID = "google-workspace-oidc"
		}
		if connectorName == "" {
			connectorName = "Google Workspace SSO"
		}

	default:
		return nil, fmt.Errorf("unsupported connector_sub_type: %s", connectorSubType)
	}

	// Serialize the OIDCConfig to JSON.
	configBytes, err := json.Marshal(oidcConfig)
	if err != nil {
		dc.logger.Errorf("Failed to marshal OIDC config: %v", err)
		return nil, fmt.Errorf("failed to marshal OIDC config: %w", err)
	}

	// Construct the Connector message.
	connector := &dexapi.Connector{
		Id:     connectorID,
		Type:   "oidc",
		Name:   connectorName,
		Config: configBytes,
	}

	// Create the CreateConnectorReq message.
	req := &dexapi.CreateConnectorReq{
		Connector: connector,
	}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the CreateConnector RPC.
	resp, err := dc.client.CreateConnector(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to create connector (%s): %v", connectorID, err)
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	if resp.AlreadyExists {
		dc.logger.Infof("Connector (%s) already exists", connectorID)
	} else {
		dc.logger.Infof("Connector (%s) created successfully", connectorID)
	}

	return resp, nil
}

// fetchEntraIDIssuer fetches the issuer URL for EntraID based on tenant ID.
func fetchEntraIDIssuer(tenantID string, logger *logrus.Logger) (string, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", tenantID)
	resp, err := http.Get(url)
	if err != nil {
		logger.Errorf("Failed to fetch OpenID configuration from %s: %v", url, err)
		return "", fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Unexpected status code %d when fetching OpenID configuration from %s", resp.StatusCode, url)
		return "", fmt.Errorf("unexpected status code %d when fetching OpenID configuration", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Failed to read OpenID configuration response: %v", err)
		return "", fmt.Errorf("failed to read OpenID configuration response: %w", err)
	}

	var config struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		logger.Errorf("Failed to parse OpenID configuration: %v", err)
		return "", fmt.Errorf("failed to parse OpenID configuration: %w", err)
	}

	if config.Issuer == "" {
		logger.Error("Issuer not found in OpenID configuration")
		return "", fmt.Errorf("issuer not found in OpenID configuration")
	}

	logger.Debugf("Fetched EntraID issuer: %s", config.Issuer)

	return config.Issuer, nil
}

// UpdateOIDCConnector updates an existing OIDC connector's configuration in Dex.
func (dc *DexClient) UpdateOIDCConnector(connectorID string, params map[string]string) (*dexapi.UpdateConnectorResp, error) {
	connectorType := strings.ToLower(params["ConnectorType"])
	connectorSubType := strings.ToLower(params["ConnectorSubType"])

	var newOIDCConfig OIDCConfig

	switch connectorType {
	case "oidc":
		switch connectorSubType {
		case "google-workspace", "entraid", "general":
			if connectorSubType == "entraid" && params["TenantID"] != "" && params["Issuer"] == "" {
				issuer, err := fetchEntraIDIssuer(params["TenantID"], dc.logger)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch issuer for entraid: %w", err)
				}
				params["Issuer"] = issuer
			}
			newOIDCConfig = OIDCConfig{
				Issuer:       params["Issuer"],
				TenantID:     params["TenantID"], // Ensure TenantID is set for entraid
				ClientID:     params["ClientID"],
				ClientSecret: params["ClientSecret"],
			}
		default:
			return nil, fmt.Errorf("unsupported connector_sub_type: %s", connectorSubType)
		}
	default:
		return nil, fmt.Errorf("unsupported connector_type: %s", connectorType)
	}

	// Serialize the new OIDCConfig to JSON.
	configBytes, err := json.Marshal(newOIDCConfig)
	if err != nil {
		dc.logger.Errorf("Failed to marshal new OIDC config: %v", err)
		return nil, fmt.Errorf("failed to marshal new OIDC config: %w", err)
	}

	// Construct the UpdateConnectorReq message.
	req := &dexapi.UpdateConnectorReq{
		Id:        connectorID,
		NewConfig: configBytes,
	}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the UpdateConnector RPC.
	resp, err := dc.client.UpdateConnector(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to update connector (%s): %v", connectorID, err)
		return nil, fmt.Errorf("failed to update connector: %w", err)
	}

	if resp.NotFound {
		dc.logger.Warnf("Connector (%s) not found for update", connectorID)
	} else {
		dc.logger.Infof("Connector (%s) updated successfully", connectorID)
	}

	return resp, nil
}

// DeleteConnectorByID deletes an existing connector from Dex based on connector ID.
func (dc *DexClient) DeleteConnectorByID(connectorID string) (*dexapi.DeleteConnectorResp, error) {
	// Construct the DeleteConnectorReq message.
	req := &dexapi.DeleteConnectorReq{
		Id: connectorID,
	}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the DeleteConnector RPC.
	resp, err := dc.client.DeleteConnector(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to delete connector (%s): %v", connectorID, err)
		return nil, fmt.Errorf("failed to delete connector: %w", err)
	}

	if resp.NotFound {
		dc.logger.Warnf("Connector (%s) not found for deletion", connectorID)
	} else {
		dc.logger.Infof("Connector (%s) deleted successfully", connectorID)
	}

	return resp, nil
}

// ListConnectors retrieves all connectors from Dex.
func (dc *DexClient) ListConnectors() ([]*dexapi.Connector, error) {
	// Create the ListConnectorReq message.
	req := &dexapi.ListConnectorReq{}

	// Create a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Execute the ListConnectors RPC.
	resp, err := dc.client.ListConnectors(ctx, req)
	if err != nil {
		dc.logger.Errorf("Failed to list connectors: %v", err)
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}

	dc.logger.Infof("Retrieved %d connectors from Dex", len(resp.Connectors))

	return resp.Connectors, nil
}

// CreateConnectorHandler handles the creation of connectors based on the type and sub-type specified in the URL.
func (dc *DexClient) CreateConnectorHandler(c echo.Context) error {
	connectorType := c.Param("connector_type")
	connectorSubType := c.Param("connector_sub_type")

	if strings.TrimSpace(connectorType) == "" {
		dc.logger.Warn("Missing connector_type in CreateConnectorHandler request")
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "connector_type is required in the URL path",
		})
	}

	connectorTypeLower := strings.ToLower(connectorType)
	creator, supported := connectorCreators[connectorTypeLower]
	if !supported {
		dc.logger.Warnf("Unsupported connector type: %s", connectorType)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unsupported connector type: %s", connectorType),
		})
	}

	// Decode the request body into CreateConnectorRequest
	var reqData CreateConnectorRequest
	if err := c.Bind(&reqData); err != nil {
		dc.logger.Errorf("Invalid request body for CreateConnectorHandler: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid request body: %v", err),
		})
	}

	// Set the ConnectorType from URL path
	reqData.ConnectorType = connectorTypeLower

	// Determine the connector_sub_type
	connectorSubTypeLower := "general" // default
	if connectorSubType != "" {
		connectorSubTypeLower = strings.ToLower(connectorSubType)
	} else {
		dc.logger.Infof("No connector_sub_type specified. Defaulting to 'general'")
	}

	// Set the ConnectorSubType in the request data
	reqData.ConnectorSubType = connectorSubTypeLower

	// Validate that the connector_sub_type is supported
	if !isSupportedSubType(connectorTypeLower, connectorSubTypeLower) {
		dc.logger.Warnf("Unsupported connector_sub_type '%s' for connector_type '%s'", connectorSubTypeLower, connectorTypeLower)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unsupported connector_sub_type '%s' for connector_type '%s'", connectorSubTypeLower, connectorTypeLower),
		})
	}

	// Perform subtype-specific validation and set default values
	switch connectorSubTypeLower {
	case "general":
		// Required: issuer, client_id, client_secret
		if strings.TrimSpace(reqData.Issuer) == "" {
			dc.logger.Warn("Missing 'issuer' for 'general' OIDC connector")
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "issuer is required for 'general' OIDC connector",
			})
		}
		// client_id and client_secret are already validated as required in the struct

		// Set default id and name if not provided
		if strings.TrimSpace(reqData.ID) == "" {
			reqData.ID = "default-oidc"
			dc.logger.Infof("No 'id' provided. Defaulting to '%s'", reqData.ID)
		}
		if strings.TrimSpace(reqData.Name) == "" {
			reqData.Name = "OIDC SSO"
			dc.logger.Infof("No 'name' provided. Defaulting to '%s'", reqData.Name)
		}

	case "entraid":
		// Required: tenant_id, client_id, client_secret
		if strings.TrimSpace(reqData.TenantID) == "" {
			dc.logger.Warn("Missing 'tenant_id' for 'entraid' OIDC connector")
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "tenant_id is required for 'entraid' OIDC connector",
			})
		}
		// client_id and client_secret are already validated as required in the struct

		// Set default id and name if not provided
		if strings.TrimSpace(reqData.ID) == "" {
			reqData.ID = "entraid-oidc"
			dc.logger.Infof("No 'id' provided. Defaulting to '%s'", reqData.ID)
		}
		if strings.TrimSpace(reqData.Name) == "" {
			reqData.Name = "Microsoft AzureAD SSO"
			dc.logger.Infof("No 'name' provided. Defaulting to '%s'", reqData.Name)
		}

	case "google-workspace":
		// Required: client_id, client_secret
		// No additional fields needed
		// client_id and client_secret are already validated as required in the struct

		// Set default id and name if not provided
		if strings.TrimSpace(reqData.ID) == "" {
			reqData.ID = "google-workspace-oidc"
			dc.logger.Infof("No 'id' provided. Defaulting to '%s'", reqData.ID)
		}
		if strings.TrimSpace(reqData.Name) == "" {
			reqData.Name = "Google Workspace SSO"
			dc.logger.Infof("No 'name' provided. Defaulting to '%s'", reqData.Name)
		}
	}

	// Additional validation through validator
	if err := dc.validate.Struct(reqData); err != nil {
		dc.logger.Errorf("Validation error in CreateConnectorHandler: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("validation error: %v", err),
		})
	}

	// Prepare parameters map with corrected key names and include sub-type
	paramsMap := map[string]string{
		"Issuer":           reqData.Issuer,
		"TenantID":         reqData.TenantID,
		"ClientID":         reqData.ClientID,
		"ClientSecret":     reqData.ClientSecret,
		"ConnectorType":    reqData.ConnectorType,
		"ConnectorSubType": reqData.ConnectorSubType, // New key for sub-type
		"id":               reqData.ID,               // Corrected to lowercase 'id'
		"name":             reqData.Name,             // Corrected to lowercase 'name'
	}

	// **[Optional]** Add logging to verify params
	dc.logger.Debugf("Creating connector with params: %+v", paramsMap)

	// Use the creator function to create the connector
	resp, err := creator(dc, paramsMap)
	if err != nil {
		dc.logger.Errorf("Error creating connector (%s/%s): %v", connectorTypeLower, connectorSubTypeLower, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("error creating connector: %v", err),
		})
	}

	response := map[string]string{
		"message": "Connector created successfully.",
	}

	if resp.AlreadyExists {
		response["message"] = "Connector already exists."
	}

	return c.JSON(http.StatusOK, response)
}

// isSupportedSubType checks if a given sub-type is supported for a connector type.
func isSupportedSubType(connectorType, subType string) bool {
	subTypes, exists := SupportedConnectors[connectorType]
	if !exists {
		return false
	}
	for _, st := range subTypes {
		if strings.ToLower(st) == subType {
			return true
		}
	}
	return false
}

// ListAndDescribeConnectorsHandler handles the GET /list and GET /list/{connector_type} endpoints.
func (dc *DexClient) ListAndDescribeConnectorsHandler(c echo.Context) error {
	connectorType := c.Param("connector_type")

	// Log the requested connector_type
	if connectorType != "" {
		dc.logger.Infof("Received request to list connectors of type: %s", connectorType)
	} else {
		dc.logger.Info("Received request to list all connectors")
	}

	// Retrieve the list of connectors from Dex
	connectors, err := dc.ListConnectors()
	if err != nil {
		dc.logger.Errorf("Error retrieving connectors: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Error retrieving connectors: %v", err),
		})
	}

	dc.logger.Infof("Total connectors retrieved from Dex: %d", len(connectors))

	type ConnectorInfo struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Name     string `json:"name"`
		Issuer   string `json:"issuer,omitempty"`
		ClientID string `json:"client_id,omitempty"`
	}

	var connectorInfos []ConnectorInfo

	for _, connector := range connectors {
		dc.logger.Debugf("Processing connector: ID=%s, Type=%s, Name=%s", connector.Id, connector.Type, connector.Name)

		// If connector_type is specified, filter connectors by type
		if connectorType != "" && strings.ToLower(connectorType) != strings.ToLower(connector.Type) {
			dc.logger.Debugf("Skipping connector (ID=%s) due to type mismatch: expected=%s, actual=%s", connector.Id, connectorType, connector.Type)
			continue
		}

		info := ConnectorInfo{
			ID:   connector.Id,
			Type: connector.Type,
			Name: connector.Name,
		}

		// If the connector is of type "oidc", attempt to extract Issuer and ClientID
		if strings.ToLower(connector.Type) == "oidc" {
			var config OIDCConfig
			if err := json.Unmarshal(connector.Config, &config); err != nil {
				dc.logger.Errorf("Failed to unmarshal OIDC config for connector (%s): %v", connector.Id, err)
			} else {
				info.Issuer = config.Issuer
				info.ClientID = config.ClientID
				// Note: Omitting ClientSecret for security reasons
			}
		}

		connectorInfos = append(connectorInfos, info)
	}

	// If a specific connector_type was requested but no connectors found, return 404
	if connectorType != "" && len(connectorInfos) == 0 {
		dc.logger.Warnf("No connectors found for type: %s", connectorType)
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("No connectors found for type: %s", connectorType),
		})
	}

	return c.JSON(http.StatusOK, connectorInfos)
}

// UpdateConnectorByIDHandler handles the updating of a connector based on connector_id in the path.
func (dc *DexClient) UpdateConnectorByIDHandler(c echo.Context) error {
	connectorID := c.Param("connector_id")
	if strings.TrimSpace(connectorID) == "" {
		dc.logger.Warn("Missing connector_id in UpdateConnectorByIDHandler request")
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "connector_id is required in the URL path",
		})
	}

	var reqData CreateConnectorRequest

	if err := c.Bind(&reqData); err != nil {
		dc.logger.Errorf("Invalid request body for UpdateConnectorByIDHandler: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("Invalid request body: %v", err),
		})
	}

	// Set the ConnectorType from URL path if not provided in the body
	if strings.TrimSpace(reqData.ConnectorType) == "" {
		dc.logger.Warn("Missing connector_type in request body, defaulting to 'oidc'")
		reqData.ConnectorType = "oidc"
	}

	// Determine the connector_sub_type
	connectorSubTypeLower := reqData.ConnectorSubType
	if strings.TrimSpace(connectorSubTypeLower) == "" {
		connectorSubTypeLower = "general" // default
	}

	reqData.ConnectorSubType = strings.ToLower(connectorSubTypeLower)

	// Validate that the connector_sub_type is supported
	if !isSupportedSubType(strings.ToLower(reqData.ConnectorType), connectorSubTypeLower) {
		dc.logger.Warnf("Unsupported connector_sub_type '%s' for connector_type '%s'", connectorSubTypeLower, reqData.ConnectorType)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unsupported connector_sub_type '%s' for connector_type '%s'", connectorSubTypeLower, reqData.ConnectorType),
		})
	}

	// Perform subtype-specific validation and set default values if needed
	switch reqData.ConnectorSubType {
	case "general":
		// Required: issuer, client_id, client_secret
		if strings.TrimSpace(reqData.Issuer) == "" {
			dc.logger.Warn("Missing 'issuer' for 'general' OIDC connector update")
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "issuer is required for 'general' OIDC connector update",
			})
		}
		// client_id and client_secret are already validated as required in the struct

	case "entraid":
		// Required: tenant_id, client_id, client_secret
		if strings.TrimSpace(reqData.TenantID) == "" {
			dc.logger.Warn("Missing 'tenant_id' for 'entraid' OIDC connector update")
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "tenant_id is required for 'entraid' OIDC connector update",
			})
		}
		// client_id and client_secret are already validated as required in the struct

	case "google-workspace":
		// Required: client_id, client_secret
		// No additional fields needed
		// client_id and client_secret are already validated as required in the struct

	default:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unsupported connector_sub_type: %s", reqData.ConnectorSubType),
		})
	}

	// Validate the request payload
	if err := dc.validate.Struct(reqData); err != nil {
		dc.logger.Errorf("Validation error in UpdateConnectorByIDHandler: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("validation error: %v", err),
		})
	}

	// Prepare parameters map
	paramsMap := map[string]string{
		"Issuer":           reqData.Issuer,
		"TenantID":         reqData.TenantID,
		"ClientID":         reqData.ClientID,
		"ClientSecret":     reqData.ClientSecret,
		"ConnectorType":    reqData.ConnectorType,
		"ConnectorSubType": reqData.ConnectorSubType, // Include sub-type if needed
		"id":               reqData.ID,               // Corrected to lowercase 'id'
		"name":             reqData.Name,             // Corrected to lowercase 'name'
	}

	// Update the connector
	resp, err := dc.UpdateOIDCConnector(connectorID, paramsMap)
	if err != nil {
		dc.logger.Errorf("Error updating connector (%s): %v", connectorID, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Error updating connector: %v", err),
		})
	}

	response := map[string]string{
		"message": "Connector updated successfully.",
	}

	if resp.NotFound {
		response["message"] = "Connector not found for update."
	}

	return c.JSON(http.StatusOK, response)
}

// DeleteConnectorByIDHandler handles the deletion of a connector based on connector_id in the path.
func (dc *DexClient) DeleteConnectorByIDHandler(c echo.Context) error {
	connectorID := c.Param("connector_id")
	if strings.TrimSpace(connectorID) == "" {
		dc.logger.Warn("Missing connector_id in DeleteConnectorByIDHandler request")
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "connector_id is required in the URL path",
		})
	}

	resp, err := dc.DeleteConnectorByID(connectorID)
	if err != nil {
		dc.logger.Errorf("Error deleting connector by ID (%s): %v", connectorID, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Error deleting connector: %v", err),
		})
	}

	response := map[string]string{
		"message": "Connector deleted successfully.",
	}

	if resp.NotFound {
		response["message"] = "Connector not found for deletion."
	}

	return c.JSON(http.StatusOK, response)
}

// GetSupportedConnectorTypesHandler handles the GET /get/supported-connector-types endpoint.
func (dc *DexClient) GetSupportedConnectorTypesHandler(c echo.Context) error {
	// Define a struct to represent each connector type and its sub-types.
	type ConnectorTypeInfo struct {
		ConnectorType string   `json:"connector_type"`
		SubTypes      []string `json:"sub_types"`
	}

	var connectors []ConnectorTypeInfo

	// Populate the connectors slice with data from SupportedConnectors.
	for ct, subTypes := range SupportedConnectors {
		connectors = append(connectors, ConnectorTypeInfo{
			ConnectorType: ct,
			SubTypes:      subTypes,
		})
	}

	// Marshal the connectors slice to JSON.
	return c.JSON(http.StatusOK, connectors)
}

// main function sets up the server and routes.
func main() {
	// Initialize Logrus logger
	logger := logrus.New()

	// Set log format to JSON for better integration with Kubernetes logging
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Set log level based on environment variable, default to info
	logLevelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevelStr {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.Infof("Logger initialized with level: %s", logger.GetLevel().String())

	// Parse command-line flags for gRPC certificates and server addresses
	caCrt := flag.String("ca-crt", "", "Path to CA certificate (optional)")
	clientCrt := flag.String("client-crt", "", "Path to client certificate (optional)")
	clientKey := flag.String("client-key", "", "Path to client key (optional)")
	dexAddress := flag.String("dex-address", "127.0.0.1:5557", "Dex gRPC server address")
	serverAddress := flag.String("server-address", ":8080", "HTTP server address")
	flag.Parse()

	// Determine if operations should be restricted to "oidc" connector types
	restrictToOIDC := true // Default to true
	if envVal, exists := os.LookupEnv("RESTRICT_TO_OIDC"); exists {
		restrictToOIDC = strings.ToLower(envVal) == "true"
	}
	if restrictToOIDC {
		logger.Info("Operations are restricted to 'oidc' connector types")
	} else {
		logger.Info("Operations are not restricted to 'oidc' connector types")
	}

	// Initialize the Dex client.
	dexClient, err := NewDexClient(*dexAddress, *caCrt, *clientCrt, *clientKey, logger, restrictToOIDC)
	if err != nil {
		logger.Fatalf("Failed to initialize Dex client: %v", err)
	}
	defer func() {
		if err := dexClient.Close(); err != nil {
			logger.Errorf("Failed to close Dex client: %v", err)
		}
	}()

	// Initialize Echo
	e := echo.New()

	// Middleware
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))
	e.Use(middleware.Recover())

	// Routes
	// Route for connectors that require a sub-type
	e.POST("/create/:connector_type/:connector_sub_type", dexClient.CreateConnectorHandler)

	// Route for connectors that do not require a sub-type (defaults to 'general')
	e.POST("/create/:connector_type", dexClient.CreateConnectorHandler)

	// Update connector by ID
	e.PUT("/update/:connector_id", dexClient.UpdateConnectorByIDHandler)

	// Delete connector by ID
	e.DELETE("/delete/:connector_id", dexClient.DeleteConnectorByIDHandler)

	// List connectors
	e.GET("/list", dexClient.ListAndDescribeConnectorsHandler)
	e.GET("/list/:connector_type", dexClient.ListAndDescribeConnectorsHandler)

	// Endpoint to get supported connector types and their sub-types
	e.GET("/get/supported-connector-types", dexClient.GetSupportedConnectorTypesHandler)

	// Start the server
	logger.Infof("Starting server on %s...", *serverAddress)
	if err := e.Start(*serverAddress); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Echo server failed to start: %v", err)
	}
}
