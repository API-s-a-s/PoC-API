/**
 * Estrategia de Exigencia de Verificación en 2 Pasos para Administradores.
 * Propósito: Auditar matemáticamente si los usuarios con privilegios de Administrador 
 * están OBLIGADOS a utilizar MFA, cruzando sus perfiles con el motor CEL.
 * Referencia: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
 */
class AdminTwoStepVerificationEnforcementStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-010", 
        valueKey: "valorPrincipal",
        noteKey: "comentario010",
        riskKey: "riesgo010",
        scoreKey: "score010"
      }
    ];

    super("Admin 2-Step Verification Enforcement Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas no encontrados en memoria).");
    }

    // =======================================================================
    // PASO 1: FILTRAR LAS POLÍTICAS DE EXIGENCIA MFA (ENFORCEMENT)
    // =======================================================================
    const enforcementPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_enforcement"));
    Logger.log(`[ID-010] Políticas de Exigencia MFA encontradas en memoria: ${enforcementPolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API (ELIMINADO)
    // Dejamos que el motor procese. Al no haber políticas, asumirá la exigencia 
    // como 'false' (por defecto de fábrica nadie está obligado).
    // =======================================================================

    // =======================================================================
    // PASO 3: AISLAR A LOS ADMINISTRADORES DEL CENSO
    // Utilizamos la variable `isAdmin` que inyectaste en core-censo.gs
    // =======================================================================
    const administradores = census.filter(user => user.isAdmin === true);
    const totalAdmins = administradores.length;

    if (totalAdmins === 0) {
      Logger.log("[ID-010] AVISO: No se encontraron usuarios con el flag isAdmin=true en el censo.");
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario010: "No se detectaron cuentas de administrador en la extracción del censo para evaluar.",
        riesgo010: "Medio",
        score010: this.calcularScoreDeRiesgo("Medio")
      };
    }

    Logger.log(`[ID-010] Evaluando la exigencia de 2SV para ${totalAdmins} Administrador(es) detectado(s).`);

    // =======================================================================
    // PASO 4: EVALUACIÓN FORENSE POR USUARIO ADMINISTRADOR
    // =======================================================================
    let adminsObligados = 0;
    
    for (const admin of administradores) {
      // 1. Vemos qué políticas aplican específicamente a ESTE administrador
      const aplicables = enforcementPolicies.filter(p => CELParserEngine.evaluate(p, admin));
      
      // 2. Resolvemos cuál gana si tiene más de una asignada
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_enforcement");

      const hasEnforcement = this._isCurrentlyEnforced(politicaGanadora);
      
      // LOG FORENSE: Mostrar cada admin y su estado de exigencia
      Logger.log(`[DEBUG ID-010] Evaluando admin: ${admin.email || admin.id} | Políticas aplicables: ${aplicables.length} | Exigencia 2SV: ${hasEnforcement}`);

      // 3. Verificamos si la política ganadora efectivamente le obliga a usar 2SV hoy
      if (hasEnforcement) {
        adminsObligados++;
      }
    }

    const porcentajeAdmins = Math.round((adminsObligados / totalAdmins) * 100);

    // =======================================================================
    // PASO 5: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // Un solo admin sin protección MFA es un riesgo ALTO.
    // =======================================================================
    let respuestaConcreta;
    let riesgo010, comentario010;

    if (porcentajeAdmins === 100) {
      respuestaConcreta = "Habilitado";
      riesgo010 = "Bajo";
      comentario010 = `El 100% de los administradores (${adminsObligados}/${totalAdmins}) tienen exigencia estricta de verificación en dos pasos.`;
    } else if (porcentajeAdmins === 0) {
      respuestaConcreta = "Deshabilitado";
      riesgo010 = "Alto";
      comentario010 = `Ningún administrador (0/${totalAdmins}) está obligado a usar la verificación en dos pasos.`;
    } else {
      respuestaConcreta = "Deshabilitado"; // O "Parcial" dependiendo de tu convención
      riesgo010 = "Alto"; // Sigue siendo ALTO porque hay admins expuestos
      comentario010 = `Vulnerabilidad detectada. Solo el ${porcentajeAdmins}% de los administradores (${adminsObligados}/${totalAdmins}) tienen exigencia de verificación en dos pasos.`;
    }

    Logger.log(`[ID-010] Métrica procesada. Resultado: ${respuestaConcreta} | Riesgo: ${riesgo010} | Admins Protegidos: ${porcentajeAdmins}%`);

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario010: comentario010,
      riesgo010: riesgo010,
      score010: this.calcularScoreDeRiesgo(riesgo010)
    };
  }

  // =======================================================================
  // HELPER: Lógica de validación de fechas de Google
  // Verifica si la política exige MFA desde una fecha válida (hoy o pasado).
  // =======================================================================
  _isCurrentlyEnforced(policy) {
    if (!policy || !policy.setting) return false;
    
    const configNode = policy.setting.value || policy.setting;
    const enforcementNode = configNode.twoStepVerificationEnforcement || configNode;
    
    // Google puede enviar la variable en diferentes formatos
    const enforcedFrom = enforcementNode.enforcedFrom || enforcementNode.enforced_from;

    if (enforcedFrom) {
      const enforcementDate = new Date(enforcedFrom);
      const today = new Date();
      // Retorna true si la fecha de exigencia ya pasó o es hoy
      return enforcementDate <= today;
    }
    
    return false;
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Handler de errores en memoria
  _buildErrorResponse(msg) {
    Logger.log(`[ID-010] ERROR: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR EN MEMORIA", 
      riesgo010: "", 
      score010: "", 
      comentario010: msg 
    };
  }
}