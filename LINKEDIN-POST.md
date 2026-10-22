# LinkedIn post drafts

Repository: https://github.com/AlexVargasV/php2shell-response-kit. Two versions: English and Spanish. LinkedIn renders no Markdown, so paste as plain text; line breaks and emoji are kept.

---

## English

🚨 If you run anything on PHP, you have work to do today.

On 21 October the PHP project shipped emergency fixes for two critical bugs, nicknamed **php2shell** (CVE-2026-109618 / CVE-2026-109619, CVSS 9.2).

Why this one is different:
• Unauthenticated remote code execution — no login, no plugin, no bad code of yours required.
• It triggers *before your application runs*. WordPress, Moodle, Magento, Laravel, a plain index.php: all the same.
• Default configurations are vulnerable. Every PHP version since 5.4 (2012).
• Exploit tooling is public. Cloudflare saw attacks 6 hours before the patch existed.
• PHP 8.1 and older will never get a fix.

Fixed versions: 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35. Update and restart your workers.

This week I went through this on three very different setups: a Moodle on a self-managed VPS with Docker, a BigBlueButton server, and a WordPress on managed hosting. Different answers for each, same questions every time: Am I exposed? Was I hit? Is there a backdoor?

I put what I learned into a small open repository:
📘 A plain-English guide: what the bugs are, why "hardening" is not enough, how to patch on every platform (Debian/Ubuntu, RHEL, Docker, cPanel, Plesk, managed hosting), and what to do on 8.1 or older.
📝 A self-assessment form: eight questions → a prioritised action plan for your situation.
🔍 A read-only check script for Linux: finds vulnerable binaries and containers, risky ini settings, worker segfaults and OOM bursts (the exploitation signature), web shells, and persistence. Produces a report and an evidence folder.
🛠️ For developers: a GitHub Action that fails pull requests pinning a vulnerable PHP (Dockerfile, compose, composer, CI), a migration guide off PHP 8.1, Renovate/Dependabot configs, and ready-to-paste nginx/Apache/Cloudflare rules.
🤖 A context file and prompts so your AI assistant helps with the right facts and safety rules.

👉 https://github.com/AlexVargasV/php2shell-response-kit

Patch first, then look back at 20–21 October. A clean log is not proof, but a segfault in php-fpm is a very loud hint.

If you administer PHP for someone else, forward this to them. If someone administers it for you, ask them one question: "Which PHP version is serving our site right now?"

#PHP #php2shell #CyberSecurity #DevOps #WordPress #Moodle #IncidentResponse #SysAdmin #WebSecurity

---

## Español

🚨 Si tienes algo corriendo en PHP, hoy tienes trabajo.

El 21 de octubre el proyecto PHP publicó parches de emergencia para dos fallos críticos, apodados **php2shell** (CVE-2026-109618 / CVE-2026-109619, CVSS 9.2).

Por qué este caso es distinto:
• Ejecución remota de código sin autenticación: sin login, sin plugin, sin un error tuyo.
• Se dispara *antes de que tu aplicación arranque*. WordPress, Moodle, Magento, Laravel, un index.php pelado: da igual.
• Las configuraciones por defecto son vulnerables. Todas las versiones desde PHP 5.4 (2012).
• Hay herramientas de explotación públicas. Cloudflare vio ataques 6 horas antes de que existiera el parche.
• PHP 8.1 y anteriores no recibirán arreglo nunca.

Versiones corregidas: 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35. Actualiza y reinicia los workers.

Esta semana pasé por esto en tres entornos muy distintos: un Moodle en VPS propio con Docker, un servidor BigBlueButton y un WordPress en hosting administrado. Respuestas diferentes, pero siempre las mismas tres preguntas: ¿Estoy expuesto? ¿Me atacaron? ¿Hay una puerta trasera?

Lo que aprendí está en un repositorio abierto (en inglés):
📘 Guía clara: qué son los fallos, por qué "endurecer" no basta, cómo parchear en cada plataforma (Debian/Ubuntu, RHEL, Docker, cPanel, Plesk, hosting administrado) y qué hacer si estás en 8.1 o menor.
📝 Un formulario de autoevaluación: ocho preguntas → plan de acción priorizado para tu caso.
🔍 Un script de solo lectura para Linux: detecta binarios y contenedores vulnerables, ajustes de riesgo, segfaults y ráfagas de OOM en los workers (la firma de explotación), webshells y persistencia. Genera informe y carpeta de evidencia.
🛠️ Para desarrolladores: una GitHub Action que hace fallar los pull requests que fijan un PHP vulnerable (Dockerfile, compose, composer, CI), una guía para salir de PHP 8.1, configuraciones de Renovate/Dependabot y reglas listas para nginx, Apache y Cloudflare.
🤖 Un archivo de contexto y prompts para que tu asistente de IA ayude con los datos correctos y reglas de seguridad.

👉 https://github.com/AlexVargasV/php2shell-response-kit

Primero parchea, después mira hacia atrás al 20 y 21 de octubre. Un log limpio no es prueba, pero un segfault en php-fpm es una pista muy ruidosa.

Si administras PHP para otros, reenvíaselo. Si alguien lo administra por ti, hazle una sola pregunta: "¿Qué versión de PHP está sirviendo nuestro sitio ahora mismo?"

#PHP #php2shell #Ciberseguridad #DevOps #WordPress #Moodle #RespuestaAIncidentes #SysAdmin #SeguridadWeb
