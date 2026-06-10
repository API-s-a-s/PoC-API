/**
 * Estrategia unificada para auditar Single Sign-On (SSO / IdP).
 * Propósito: Cruza los perfiles SSO creados con las asignaciones reales activas en la organización.
 * Referencia: https://docs.cloud.google.com/identity/docs/reference/rest/v1/inboundSsoAssignments
 */
class SsoAuditStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { id: "ID-001", valueKey: "valorPrincipal", noteKey: "comentario001", riskKey: "riesgo001", scoreKey: "score001" },
      { id: "ID-002", valueKey: "valorSecundario", noteKey: "comentario002", riskKey: "riesgo002", scoreKey: "score002" }
    ];
    
    super("SSO Identity Providers", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
    
    // Endpoint inicial: Solo para buscar los perfiles creados
    const filter = `customer=="customers/${this.customerId}"`;
    this.url = `https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles?filter=${encodeURIComponent(filter)}`;
  }

  // El Facade llama a este método para hacer la primera petición de red
  getRequestConfig() {
    return { url: this.url, method: "get", muteHttpExceptions: true };
  }

  // Una vez que el Facade obtiene la respuesta, nos pasa el JSON para procesarlo
  parseResponse(json) {
    // =======================================================================
    // PASO 1: MANEJO DE ERRORES DE RED
    // =======================================================================
    if (json.error) {
      Logger.log(`[ID-001] Error de API: ${json.error.message}`);
      return this._buildErrorResponse(`Fallo de red: ${json.error.message}`);
    }
    
    // =======================================================================
    // PASO 2: EXTRAER PERFILES SSO
    // Buscamos cuántos proveedores de identidad (ej. Azure) se han configurado.
    // Si la lista es muy larga, usamos nuestro paginador universal.
    // =======================================================================
    let perfilesSso = json.inboundSamlSsoProfiles || [];
    if (json.nextPageToken) {
      const todos = this.fetchPaginated(this.url, "inboundSamlSsoProfiles");
      if (todos) perfilesSso = todos;
    }

    const totalPerfiles = perfilesSso.length;
    
    // =======================================================================
    // Si no hay perfiles creados, abortamos temprano y reportamos inhabilitado.
    // =======================================================================
    if (totalPerfiles === 0) {
      Logger.log("[ID-001] Respuesta de la API: 0 perfiles configurados.");
      return this._buildEmptyResponse();
    }

    const nombresPerfiles = perfilesSso.map(p => p.displayName).join(", ");
    Logger.log(`[ID-001] Respuesta de la API (Perfiles): Se encontraron ${totalPerfiles} perfiles base.`);

    // =======================================================================
    // PASO 4: OBTENER ASIGNACIONES VIVAS
    // endpoint para ver a qué OUs o Grupos se les está aplicando realmente.
    // =======================================================================
    const filterAssignments = `customer=="customers/${this.customerId}"`;
    const urlAssignments = `https://cloudidentity.googleapis.com/v1/inboundSsoAssignments?filter=${encodeURIComponent(filterAssignments)}`;
    const asignacionesVivas = this.fetchPaginated(urlAssignments, "inboundSsoAssignments") || [];

    let perfilesActivosUnicos = new Set();
    let targetsDetectados = []; // Registramos si se aplica a OUs o Grupos
    
    for (const asignacion of asignacionesVivas) {
      // Verificamos si la asignación es de tipo SSO válido
      if (asignacion.ssoMode === "SAML_SSO" || asignacion.ssoMode === "OIDC_SSO") {
        const perfilVinculado = asignacion.samlSsoProfile || asignacion.ssoProfile;
        
        if (perfilVinculado) {
          perfilesActivosUnicos.add(perfilVinculado);
          
          // Clasificamos dónde se está aplicando según la documentación oficial
          if (asignacion.targetOrgUnit) targetsDetectados.push("Unidad Organizativa");
          if (asignacion.targetGroup) targetsDetectados.push("Grupos (Excepciones)");
        }
      }
    }

    // =======================================================================
    // PASO 5: CALCULAR ADOPCIÓN Y PREPARAR TEXTOS
    // Comparamos los perfiles creados vs los que realmente tienen asignaciones.
    // =======================================================================
    const totalActivos = perfilesActivosUnicos.size;
    const porcentajeNum = Math.round((totalActivos / totalPerfiles) * 100);
    
    // Unificamos el texto para que sea informativo (Ej. "Unidad Organizativa y Grupos")
    const targetsUnicos = [...new Set(targetsDetectados)].join(" y ") || "Desconocido";

    Logger.log(`[ID-002] Respuesta de la API (Asignaciones): ${totalActivos} de ${totalPerfiles} en uso. Aplicado mediante: ${targetsUnicos}`);

    // =======================================================================
    // PASO 6: ASIGNACIÓN DE RIESGOS Y RETORNO
    // preparamos las métricas para ambas simultáneamente.
    // =======================================================================
    
    // Métrica ID-001: Riesgo sobre la existencia de perfiles
    let riesgo001 = "Bajo";
    let comentario001 = `Se identificaron ${totalPerfiles} perfiles SSO declarados: [${nombresPerfiles}]. Su alteración puede requerir aprobación multipartita.`;

    // Métrica ID-002: Riesgo sobre la asignación/uso de esos perfiles
    let riesgo002, comentario002;
    
    if (porcentajeNum === 0) {
      riesgo002 = "Alto";
      comentario002 = "Ningún perfil de autenticación mapeado está haciendo uso operativo de SSO. Validar si hay cambios pendientes de aprobación.";
    } else if (porcentajeNum === 100) {
      riesgo002 = "Bajo";
      comentario002 = `El 100% de los perfiles SSO configurados tienen una redirección activa mediante asignaciones dirigidas a: ${targetsUnicos}.`;
    } else {
      riesgo002 = "Medio";
      comentario002 = `Implementación parcial. Solo el ${porcentajeNum}% de los perfiles configurados reciben aserciones de identidad vigentes.`;
    }

    return {
      name: this.name,
      // Salidas para ID-001
      valorPrincipal: `${totalPerfiles} Configurados`, 
      comentario001: comentario001,
      riesgo001: riesgo001,
      score001: this.calcularScoreDeRiesgo(riesgo001),
      
      // Salidas para ID-002
      valorSecundario: porcentajeNum === 0 ? "Inhabilitado" : (porcentajeNum === 100 ? "Habilitado" : "Parcial"), 
      comentario002: comentario002,
      riesgo002: riesgo002,
      score002: this.calcularScoreDeRiesgo(riesgo002)
    };
  }

  // Convierte el texto "Alto", "Medio", "Bajo" en un número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Función de apoyo cuando la organización no tiene SSO configurado
  _buildEmptyResponse() {
    return {
      name: this.name,
      valorPrincipal: "Inhabilitado",
      riesgo001: "Alto",
      score001: 1,
      comentario001: "La organización no cuenta con perfiles SSO activos o su creación espera aprobación multipartita.",
      valorSecundario: "Inhabilitado",
      riesgo002: "Alto",
      score002: 1,
      comentario002: "Ningún perfil de autenticación en la organización está haciendo uso de configuración SSO."
    };
  }

  // Función de apoyo en caso de que Google arroje error 500 o 403
  _buildErrorResponse(msg) {
    return { 
      name: this.name,
      valorPrincipal: "ERROR API", riesgo001: "Medio", score001: 2, comentario001: msg,
      valorSecundario: "ERROR API", riesgo002: "Medio", score002: 2, comentario002: msg
    };
  }
}