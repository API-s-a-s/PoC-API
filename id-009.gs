/**
 * Estrategia de Exigencia de Verificación en 2 Pasos (2SV Enforcement) para Usuarios Regulares.
 * Propósito: Auditar si la organización OBLIGA a los usuarios (excluyendo Administradores) a utilizar MFA.
 * Referencia: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
 */
class TwoStepVerificationEnforcementPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-009", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario009", 
        riskKey: "riesgo009", 
        scoreKey: "score009" 
      }
    ];
    
    super("2-Step Verification Enforcement Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE EXIGENCIA MFA
    // Buscamos usando .includes() para ignorar el prefijo 'settings/'
    // =======================================================================
    const enforcementPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_enforcement"));
    Logger.log(`[ID-009] Políticas de exigencia MFA encontradas en memoria: ${enforcementPolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API
    // Por defecto de fábrica, Google NO obliga a usar 2SV (es opcional).
    // Si la API no envía datos, asumimos este estado predeterminado.
    // =======================================================================
    if (enforcementPolicies.length === 0) {
      Logger.log("[DEBUG ID-009] ALERTA: La API no retorna datos para exigencia de 2SV.");
      return {
        name: this.name,
        valorPrincipal: "empty.",
        comentario009: "omitió datos.",
        riesgo009: "",
        score009: ""
      };
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // Buscamos la regla general que aplica a todo el dominio (sin 'entity.')
    // =======================================================================
    const rootPolicy = enforcementPolicies.find(p => !(p.query || "").includes("entity."));
    
    let isRootEnforced = false; // Por defecto es opcional
    
    if (rootPolicy && rootPolicy.setting) {
      isRootEnforced = this._isEnforced(rootPolicy);
    }

    const estadoPrincipal = isRootEnforced ? "Obligatorio" : "Habilitad0";
    Logger.log(`[ID-009] Raíz de la Org: Exigencia de 2SV = ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: AISLAR A LOS USUARIOS REGULARES DEL CENSO
    // Filtramos excluyendo explícitamente a los administradores.
    // =======================================================================
    const usuariosRegulares = census.filter(user => user.isAdmin !== true);
    const totalRegulares = usuariosRegulares.length;

    if (totalRegulares === 0) {
      Logger.log("[ID-009] AVISO: No se encontraron usuarios regulares en el censo (¿Todos son Admins?).");
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario009: "No se detectaron cuentas de usuarios regulares para evaluar.",
        riesgo009: "",
        score009: ""
      };
    }

    Logger.log(`[ID-009] Evaluando la exigencia de 2SV para ${totalRegulares} Usuario(s) Regular(es).`);

    // =======================================================================
    // PASO 5: CALCULAR PORCENTAJE DE OBLIGATORIEDAD (CENSO REGULAR)
    // Usamos el motor CEL para cruzar las políticas contra los usuarios
    // =======================================================================
    let usuariosObligados = 0;
    let usuariosOpcionales = 0;
    
    for (const user of usuariosRegulares) {
      const aplicables = enforcementPolicies.filter(p => CELParserEngine.evaluate(p, user));
      
      // El motor usará el _maxReducer para decidir qué regla prevalece si hay conflicto
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_enforcement");

      if (this._isEnforced(politicaGanadora)) {
        usuariosObligados++;
      } else {
        usuariosOpcionales++;
      }
    }

    // Calculamos el % de USUARIOS REGULARES a los que se les EXIGE usar el 2SV
    const porcentajeObligados = Math.round((usuariosObligados / totalRegulares) * 100);
    
    // =======================================================================
    // PASO 6: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // Si es obligatorio a nivel raíz el riesgo es Bajo, de lo contrario Alto.
    // El comentario solo mostrará el porcentaje exacto de cobertura.
    // =======================================================================
    let riesgo = isRootEnforced ? "Bajo" : "Alto";
    let comentario = `${porcentajeObligados}%`; 
    
    Logger.log(`[ID-009] Métrica procesada. Riesgo: ${riesgo}. Obligatorio para: ${porcentajeObligados}% de usuarios regulares.`);

    return {
      name: this.name,
      valorPrincipal: estadoPrincipal, 
      comentario009: comentario,
      riesgo009: riesgo,
      score009: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  // =======================================================================
  // HELPER: Lógica de validación de fechas de Google
  // Verifica si la fecha de obligación es hoy o si está en el pasado.
  // =======================================================================
  _isEnforced(policy) {
    if (!policy || !policy.setting) return false;

    const configNode = policy.setting.value || policy.setting;
    const enforcementNode = configNode.twoStepVerificationEnforcement || configNode;
    
    // Google puede enviar la variable en diferentes formatos según la versión de la API
    const enforcedFrom = enforcementNode.enforcedFrom || enforcementNode.enforced_from;

    if (enforcedFrom) {
      const enforcementDate = new Date(enforcedFrom);
      const today = new Date();
      // Solo es obligatorio si la fecha límite ya se cumplió o es hoy
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
    Logger.log(`[ID-009] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo009: "",
      score009: "",
      comentario009: msg
    };
  }
}