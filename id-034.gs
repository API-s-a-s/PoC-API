/**
 * Estrategia para auditar si los Super Administradores tienen acceso a Google Vault.
 * Combina dos fuentes de datos:
 *   1. Censo en RAM (O(1)): Identifica a los Super Admins globales.
 *   2. Vault Service Status: Evalúa si el servicio está habilitado para la OU Raíz.
 *      - La Policy API de Google omite la política cuando Vault usa su estado por defecto
 *        (habilitado para todos). Respuesta vacía ({}) = habilitado por defecto.
 *
 * Requerimiento del assessment:
 *   "Super admin (global) / Permitir acceso a Google Vault (deshabilitar el servicio para evitar acceso)"
 *   Best practice: Deshabilitar Vault para Super Admins para evitar acceso no autorizado a eDiscovery.
 *
 * Contiene la lógica de negocio para ID-034.
 */
class VaultServiceStatusStrategy extends ApiStrategy {
  constructor(customerId, superAdminRoleId) {
    const configIDs = [
      { 
        id: "ID-034", 
        valueKey: "valorPrincipal",
        noteKey: "comentario034",
        riskKey: "riesgo034",
        scoreKey: "score034"
      }
    ];
    super("Google Vault Super Admin Access Audit", configIDs);
    this.customerId = customerId;
    this.superAdminRoleId = superAdminRoleId || null;
    this.category = "Administración";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-034 (VAULT + SUPER ADMINS) ==========");

    // =====================================================================
    // PASO 1: Identificar Super Admins globales desde el censo en RAM
    // =====================================================================
    const totalAdmins = census.filter(u => u.isAdmin).length;
    const superAdminsList = [];

    for (const user of census) {
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      const isSuperAdmin = user.adminRoles.some(role => 
        (role.roleId === this.superAdminRoleId || role.roleName.toLowerCase().includes("super admin"))
        && role.scopeType === "CUSTOMER"
      );

      if (isSuperAdmin) {
        superAdminsList.push(user.email || user.id);
      }
    }

    const superAdminCount = superAdminsList.length;
    Logger.log(`[ID-034] Super Admins globales detectados: ${superAdminCount}`);
    if (superAdminCount > 0) {
      Logger.log(`[ID-034] Cuentas Super Admin: ${superAdminsList.join(", ")}`);
    }

    // =====================================================================
    // PASO 2: Evaluar el estado del servicio de Vault
    // La Policy API de Google omite la política si Vault usa el estado por
    // defecto del sistema (habilitado para todos). Consultamos igualmente
    // para detectar si existe una política explícita que lo deshabilite.
    // =====================================================================
    let vaultStatus = "Habilitado (Por defecto)";
    let vaultExplicitlyDisabled = false;

    try {
      const filter = `customer=="customers/${this.customerId}" && setting.type=="vault.service_status"`;
      const url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
      
      const token = ScriptApp.getOAuthToken();
      const response = UrlFetchApp.fetch(url, {
        method: "get",
        headers: { Authorization: `Bearer ${token}` },
        muteHttpExceptions: true
      });

      const json = JSON.parse(response.getContentText());
      Logger.log(`[ID-034] Payload Vault API:\n${JSON.stringify(json, null, 2)}`);

      const policies = json.policies || [];

      if (policies.length > 0) {
        // Existe una política explícita: evaluamos si Vault está deshabilitado
        const rootPolicy = policies.find(p => {
          const query = (p.policyQuery && p.policyQuery.query) || (p.query || "");
          return !query.includes("entity.");
        });

        if (rootPolicy && rootPolicy.setting) {
          const nodeStr = JSON.stringify(rootPolicy.setting).toUpperCase();
          const isEnabled = nodeStr.includes('"STATE":"ENABLED"') || 
                            nodeStr.includes('"SERVICESTATE":"ENABLED"') ||
                            nodeStr.includes('"ENABLED":TRUE') ||
                            nodeStr.includes('"STATE":"ON"') ||
                            nodeStr.includes('"SERVICESTATE":"ON"') ||
                            nodeStr.includes('"STATE":TRUE') ||
                            nodeStr.includes('"SERVICESTATE":TRUE') ||
                            nodeStr.includes('"VALUE":TRUE');

          if (isEnabled) {
            vaultStatus = "Habilitado (Explícito)";
          } else {
            vaultStatus = "Deshabilitado (Explícito)";
            vaultExplicitlyDisabled = true;
          }
        }
      }
      // Si policies.length === 0, mantenemos "Habilitado (Por defecto)"

    } catch (e) {
      Logger.log(`[ID-034] Error al consultar Vault API: ${e.message}`);
      vaultStatus = "Habilitado (Por defecto - Error en consulta)";
    }

    Logger.log(`[ID-034] Estado del servicio Vault: ${vaultStatus}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-034 ==========");

    // =====================================================================
    // PASO 3: Lógica de riesgo combinada (Super Admins + Vault)
    // =====================================================================
    let respuestaConcreta;
    let riesgo034, comentario034;

    if (vaultExplicitlyDisabled) {
      // Best practice cumplida: Vault está deshabilitado
      respuestaConcreta = "Deshabilitado";
      riesgo034 = "Bajo";
      comentario034 = `Postura segura. El servicio de Google Vault está explícitamente deshabilitado a nivel global. Los ${superAdminCount} Super Administrador(es) del dominio no pueden acceder a datos de eDiscovery ni retenciones legales a través de Vault.`;
    } else if (superAdminCount > 0) {
      // Vault habilitado (default o explícito) Y existen Super Admins → Riesgo
      respuestaConcreta = vaultStatus;
      riesgo034 = "Alto";
      comentario034 = `ALERTA: El servicio de Google Vault se encuentra ${vaultStatus.toLowerCase()} y ${superAdminCount} cuenta(s) Super Admin (${superAdminsList.join(", ")}) tienen acceso completo al servicio. Esto les permite acceder a datos de eDiscovery, retenciones legales y búsquedas forenses de todo el dominio. Se recomienda deshabilitar el acceso a Vault para los Super Administradores y delegar funciones de eDiscovery a roles específicos con privilegios limitados.`;
    } else {
      // Vault habilitado pero no hay Super Admins (improbable pero defensivo)
      respuestaConcreta = vaultStatus;
      riesgo034 = "Bajo";
      comentario034 = `El servicio de Vault se encuentra ${vaultStatus.toLowerCase()}, pero no se detectaron cuentas con el rol de Super Administrador global en el dominio.`;
    }

    Logger.log(`[LOG] Vault + Super Admin Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo034}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario034: comentario034,
      riesgo034: riesgo034,
      score034: this.calcularScoreDeRiesgo(riesgo034)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-034] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo034: "Medio",
      score034: 2,
      comentario034: msg
    };
  }
}
