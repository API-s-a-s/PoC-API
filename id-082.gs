/**
 * Estrategia para auditar las listas de remitentes bloqueados (Blocked Sender Lists) de Gmail.
 * Evalúa la cantidad de dominios y correos explícitamente vetados por la organización.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-082.
 */
class GmailBlockedSenderListsStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-082
    const configIDs = [
      { 
        id: "ID-082", 
        valueKey: "valorPrincipal", // Retornará el número entero de remitentes bloqueados
        noteKey: "comentario082",
        riskKey: "riesgo082",
        scoreKey: "score082"
      }
    ];

    super("Gmail Blocked Senders Audit", configIDs);
    
    // Aplicamos el filtro exacto de la API para 'gmail.blocked_sender_lists'
    const filter = `customer=="customers/${customerId}" && setting.type=="gmail.blocked_sender_lists"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Email y DNS";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] Blocked Senders Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo082: "Medio",
        score082: 2,
        comentario082: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide auditar técnicamente las listas de dominios y direcciones de correo electrónico bloqueadas."
      };
    }

    let blockedCount = 0;

    // 2. PARSEO DE POLÍTICAS EN LA BETA DE CLOUD IDENTITY
    if (json.policies && json.policies.length > 0) {
      const setting = json.policies[0].setting || {};
      
      // Soportamos variaciones de nodo en la API beta
      const blockedNode = setting.gmailBlockedSenderLists || setting.blockedSenderLists || setting;
      
      // Buscamos el arreglo de direcciones o dominios bloqueados
      const senders = blockedNode.blockedSenders || blockedNode.addresses || blockedNode.senders || [];
      blockedCount = senders.length;
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo082, comentario082;

    if (blockedCount === 0) {
      // Caso 1: Lista vacía (Riesgo Medio por falta de bloqueos manuales)
      riesgo082 = "Medio";
      comentario082 = "La lista de remitentes bloqueados (Blocklist) se encuentra vacía. La organización no ha configurado bloqueos explícitos para dominios o direcciones de correo maliciosas comprobadas, dependiendo exclusivamente de los filtros automatizados y globales de Google Workspace.";
    } else {
      // Caso 2: Existen remitentes vetados (Seguro / Proactivo)
      riesgo082 = "Bajo";
      comentario082 = "Indica la cantidad de dominios o direcciones de correo electrónico explícitamente vetados. La organización mantiene listas de bloqueo activas como medida proactiva para rechazar correos provenientes de atacantes conocidos, mitigando campañas recurrentes de phishing o spam.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Blocked Senders Audit: Se detectaron ${blockedCount} remitentes en la lista negra. | Riesgo: ${riesgo082}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: blockedCount,
      comentario082: comentario082,
      riesgo082: riesgo082,
      score082: this.calcularScoreDeRiesgo(riesgo082)
    };
  }
}