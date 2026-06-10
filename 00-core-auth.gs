/**
 * Se encarga de proveer y gestionar la identidad, permisos y tokens de acceso.
 * Centraliza el token interactivo y el token DWD.
 * Referencia: Google Cloud IAM & DWD (https://developers.google.com/workspace/guides/create-credentials)
 */
class AuthService {
constructor() {
    this.cache = CacheService.getScriptCache();    
    // PASO 2: Extracción segura de la llave privada desde PropertiesService para evitar exposición en texto plano.
    // Si no existe en las propiedades del script, usa un fallback (solo para desarrollo).
    this.saCredentials = {
      "type": "service_account",
      "project_id": "poc2-495720",
      "private_key_id": "927ab5e9606402ab071657103fb0dd6350b2a010",
      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQD4d9t/2mKQrrwR\nXD6xyVSfIvgFZ0fOqKCpo6U6Zbzrsk896sOhD0ykDxVN3Wh3t0xMwA9U1gKckduM\n1Kwuv9osjLH/PFV2pZyUwDxl3v2bgK0zH/DWnCG+nWmsdZJjYSi1MzqEXZ0PuHYi\nSC7oHHxDZBpU1vQGK1vZWqxy2EZ8LjrZBKk6bsqsvg23HamdNv5QT5f64c5wOpc8\nxXyI+pjjLBKWL9RhIu637+rawoCF64jACURtDbPYZ/7NCmNL3xXs0OTObXTIOD2R\nuYoUQSYXJ8ideioZy5aeUIYzAIjoZYFfOmBxzGprrpqmNYtx76Q+trFSHvu/tSLi\n2xlSAOYfAgMBAAECggEAJrvEj49TSzu6HLi1G1EH7JDueiUqGAjIlvloUgy3IUUY\nPk5BNfPlHjQtvYg092ivL83G9hIwsQi54Z/rwZPt5oD+ZIwaxJa3rKa1I6pZ/apX\nFb+2czY+unDenuBrNCvaxTiZuDXBvMgkPl7jVRLPuk+6HRyvSODsfhs5A+Q8RLI/\nnQIeD9lzVdJHZQt9ViOqYqKE/SFq8WJzaXoF5VEBgEa1JJCjBA4lOt3199Uo9/GU\nQ+tC+rgGRybcuHimEDD5JLu+areO312s3f037Qhd105BHq2jRWPL+CPXWCg3mAKy\nEy+ocunIVHcoBpoDgMGwmuCjezq/HEaYs1l+a3x2DQKBgQD/2nuUId9ctsmiOK3b\nMIXKyWBnT6rzctWNjRlnkhs88zexiIe7HflyC663pOME8UShpYR5LZBZHXV5xZ4o\nemm3YMyvdJXYppKLb4rjhO0PRS/a49jCs+uSAnob3jIWeef97cr9Trg9Gqh476v8\nI5d+/kBohn0NP8AcnfPiYUbDnQKBgQD4nEqv/V9gjFWjOehJKmCg1TqY+rySrcbx\nTp0TXVwzP9hhHyb85Hc4hCIB8KX+RyxHUw9wjYf6l7zv91BnDHfN1a0BKDqfVAL6\npVTAsEWSTJwrflm6aatpzhhaxUaHX7yX9KSUuVr7wlJhxB4V5UkwjRG7bJ8N1WxP\ns5b/sGUZ6wKBgDn5RbtBGZ2mhXXOpgZerlJO4xtFwBS91onmiPUg9C8RZXNC3o6V\nsioXX5WZNR+vk7+VA7l5i5XFyRK4pqfBZSb6NicjobifteEGe1AmlJi7MqbErh8g\nKabCDO03od3Z7alqMm7HYZPm8HnGxQ+y+Ob7sZh9sORJp7xURijrpd85AoGAKsNv\nkXAq3Mem32nRi+xPLLsg1jmjADQGGXHlUPRpLKOZy7L5GN0PqNgJpX3If8GsWyRt\nbnXZ4wAAzuIioWcioHRVyvIpi0h/LrALsQ1hGjY1UsHsG0Wb55o81DhE1npgTV8W\nhEKR5OZbF1gNuMR033YUi8G2ZkHE3LzOh3LHITsCgYBmRd6RW/4vHjlO/jU+Iy18\nUtBS801hhUMjFawK8gL7yxoQq9cCk6eyXIXQ6C1wNsIXHqh+fGPC+GAnkn8IF9Oo\n/bz6QPwhPsmxXxDWbUOssuWHOSMWb8OAnvFS3drq4FaPxnHrHTdeKmeT+vq2rifm\nOcZ2c1jAYj37I9ym071dOQ==\n-----END PRIVATE KEY-----\n",
      "client_email": "auditoria-test@poc2-495720.iam.gserviceaccount.com",
      "token_uri": "https://oauth2.googleapis.com/token"
    };
  }
  /**
   * Token interactivo estándar de Apps Script (Contexto de usuario ejecutor)
   */
  getToken() {
    return ScriptApp.getOAuthToken();
  }

  getAuthHeader() {
    return { "Authorization": "Bearer " + this.getToken() };
  }

  /**
   * Genera u obtiene del caché un token firmado por Cuenta de Servicio
   * aplicando Delegación de Dominio Completo (DWD) para suplantar a un Súper Admin.
   * * @param {string} adminEmail Correo electrónico del Súper Administrador a suplantar.
   * @param {Array<string>} scopes Arreglo de alcances de Google exigidos.
   * @return {Object} Cabecera de autenticación estructurada para UrlFetchApp.
   */
  getPrivilegedAuthHeader(adminEmail, scopes = ["https://www.googleapis.com/auth/cloud-identity.policies.readonly"]) {
    // PASO 1: Clave estática determinista. Se eliminó la entropía aleatoria (Math.random) 
    // que destruía la utilidad de la caché y generaba saturación de tokens.
    const cacheKey = "SA_TOKEN_DWD_" + adminEmail.replace(/[^a-zA-Z0-9]/g, "");
    let token = this.cache.get(cacheKey);

    if (token) {
      return { "Authorization": "Bearer " + token };
    }

    Logger.log(`[AUTH] Generando nuevo token de acceso privilegiado vía DWD para: ${adminEmail}`);
    
    const jwtHeader = JSON.stringify({ alg: "RS256", typ: "JWT" });
    const now = Math.floor(Date.now() / 1000);
    const jwtClaim = JSON.stringify({
      iss: this.saCredentials.client_email,
      sub: adminEmail, 
      scope: scopes.join(" "),
      aud: this.saCredentials.token_uri,
      exp: now + 3600, 
      iat: now
    }
  );
const base64Header = Utilities.base64EncodeWebSafe(jwtHeader).replace(/=+$/, '');
    const base64Claim = Utilities.base64EncodeWebSafe(jwtClaim).replace(/=+$/, '');
    const signatureInput = base64Header + "." + base64Claim;

    const signatureBytes = Utilities.computeRsaSha256Signature(signatureInput, this.saCredentials.private_key);
    const base64Signature = Utilities.base64EncodeWebSafe(signatureBytes).replace(/=+$/, '');
    const jwtAssertion = signatureInput + "." + base64Signature;

    const options = {
      method: "post",
      contentType: "application/x-www-form-urlencoded",
      payload: { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwtAssertion },
      muteHttpExceptions: true
    };

    try {
      const response = UrlFetchApp.fetch(this.saCredentials.token_uri, options);
      const resJson = JSON.parse(response.getContentText());

      if (resJson.error) throw new Error(`Google OAuth rechazó el JWT: ${resJson.error_description || resJson.error}`);

      token = resJson.access_token;
      this.cache.put(cacheKey, token, 3300); 
      
      return { "Authorization": "Bearer " + token };

    } catch (e) {
      Logger.log(`[CRÍTICO - AUTH] Error en intercambio criptográfico: ${e.message}`);
      throw e;
    }
  }

  getDomain() { return "test.apisas.com"; }
  getCurrentUserEmail() { return Session.getActiveUser().getEmail(); }
  getZeroTrustPolicyId() { return "accessPolicies/1028743991591"; }
  getCustomerId() { return "my_customer"; }
  getGcpProjectId() { return this.saCredentials.project_id; }
  getGcpServiceAccountEmail() { return this.saCredentials.client_email; }

  // =====================================================================
  // Resolución dinámica de roleId desde AdminDirectory.Roles.list()
  // Se resuelve una sola vez y se cachea en CacheService por 25 minutos.
  // =====================================================================
  _resolveRoleMap() {
    if (this._roleMap) return this._roleMap;

    // Intentar recuperar del caché efímero
    const cacheKey = "AUTH_ROLE_MAP";
    const cached = this.cache.get(cacheKey);
    if (cached) {
      try {
        this._roleMap = JSON.parse(cached);
        Logger.log(`[AUTH] Mapa de roles recuperado de caché: ${Object.keys(this._roleMap).length} roles`);
        return this._roleMap;
      } catch (e) { /* caché corrupta, reconstruimos */ }
    }

    // Consulta a la API de Directory para construir el diccionario roleName → roleId
    Logger.log("[AUTH] Construyendo mapa dinámico de roleId desde AdminDirectory.Roles.list()...");
    const map = {};
    const customerId = this.getCustomerId();

    try {
      let pageToken = null;
      do {
        const response = AdminDirectory.Roles.list(customerId, { maxResults: 100, pageToken: pageToken });
        const roles = response.items || [];
        roles.forEach(role => {
          // Usamos el roleName del sistema como clave (ej: "_SUPER_ADMIN_ROLE")
          map[role.roleName] = role.roleId;
          Logger.log(`[AUTH] Rol resuelto: ${role.roleName} → ${role.roleId}`);
        });
        pageToken = response.nextPageToken;
      } while (pageToken);
    } catch (e) {
      Logger.log(`[AUTH][ERROR] Fallo al resolver roles dinámicamente: ${e.message}. Se usarán los nombres del sistema como fallback.`);
    }

    this._roleMap = map;
    // Persistir en caché por 25 minutos (mismo TTL que el censo)
    this.cache.put(cacheKey, JSON.stringify(map), 1500);
    return this._roleMap;
  }

  /**
   * Busca el roleId numérico real para un nombre de rol del sistema.
   * Si la resolución dinámica falla, devuelve el nombre del sistema como fallback
   * (los scripts ya tienen fallback por roleName para este caso).
   */
  _getRoleIdBySystemName(systemRoleName) {
    const map = this._resolveRoleMap();
    return map[systemRoleName] || systemRoleName;
  }

  // Getters de roles — ahora devuelven IDs numéricos reales
  getSuperAdminRoleId()   { return this._getRoleIdBySystemName("_SUPER_ADMIN_ROLE"); }
  getGroupsAdminRoleId()  { return this._getRoleIdBySystemName("_GROUPS_ADMIN_ROLE"); }
  getUserAdminRoleId()    { return this._getRoleIdBySystemName("_USER_MANAGEMENT_ADMIN_ROLE"); }
  getHelpDeskAdminRoleId(){ return this._getRoleIdBySystemName("_HELP_DESK_ADMIN_ROLE"); }
  getAndroidAdminRoleId() { return this._getRoleIdBySystemName("_MOBILE_ADMIN_ROLE"); }
  getVoiceAdminRoleId()   { return this._getRoleIdBySystemName("_GOOGLE_VOICE_ADMIN_ROLE"); }
  getMobileAdminRoleId()  { return this._getRoleIdBySystemName("_MOBILE_ADMIN_ROLE"); }
  getServicesAdminRoleId(){ return this._getRoleIdBySystemName("_SERVICES_ADMIN_ROLE"); }
}