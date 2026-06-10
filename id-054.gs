/**
 * Estrategia para auditar eventos de instalación de aplicaciones de administrador.
 * Busca eventos relacionados con instalación y delegación en los registros de auditoría.
 * Utiliza Admin SDK Reports API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-054
 */
class AdminAppInstallEventStrategy extends ApiStrategy {
  constructor() { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-054 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-054", 
        valueKey: "valorPrincipal", // Entregará el número entero de eventos detectados
        noteKey: "comentario054",
        riskKey: "riesgo054",
        scoreKey: "score054"
      }
    ];

    super("Admin App Install Events Audit", configIDs);
    
    // Traemos el registro de administrador para procesarlo localmente (evita errores de manifest)
    this.url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin`;
    this.category = "Integración de aplicaciones";
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
      Logger.log(`[ERROR] Reports API (Admin Installs): ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo054: "Medio",
        score054: 2,
        comentario054: "Error de lectura, conectividad o permisos insuficientes en la API Reports que impide consultar los registros de actividad administrativa y contabilizar los eventos de instalación."
      };
    }

    let installEventsCount = 0;

    // Si la API responde correctamente, iteramos sobre los eventos para filtrar localmente
    if (json.items && json.items.length > 0) {
      json.items.forEach(item => {
        if (item.events) {
          item.events.forEach(event => {
            const eventName = (event.name || "").toUpperCase();
            
            // FILTRO: Buscamos variaciones de instalación de apps y autorizaciones de clientes API
            if (eventName.includes("INSTALL") || 
                eventName.includes("MARKETPLACE") || 
                eventName === "AUTHORIZE_API_CLIENT_ACCESS") {
              installEventsCount++;
            }
          });
        }
      });
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo054, comentario054;

    if (installEventsCount === 0) {
      // Caso 1: No se encontraron eventos de instalación recientes
      riesgo054 = "Bajo";
      comentario054 = "La bitácora de auditoría no registra eventos recientes de instalación de aplicaciones del Marketplace ni autorizaciones de acceso a clientes API ejecutadas por un administrador en el dominio.";
    } else {
      // Caso 2: Existen eventos recientes
      riesgo054 = "Medio";
      comentario054 = "Indica la cantidad de eventos recientes registrados en la bitácora de auditoría correspondientes a instalaciones de aplicaciones del Marketplace o autorizaciones de acceso a clientes API ejecutadas por un administrador.";
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Admin Install Audit: Se detectaron ${installEventsCount} eventos de instalación/autorización. | Riesgo: ${riesgo054}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: installEventsCount,
      comentario054: comentario054,
      riesgo054: riesgo054,
      score054: this.calcularScoreDeRiesgo(riesgo054)
    };
  }
}