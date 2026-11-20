# Contexto para trabajar en GEMSA · Control de Salidas

Lee todo antes de tocar nada.

## El proyecto
- Registro de salidas y regresos de las unidades (vehículos) de GEMSA. Un solo Cloudflare Worker (`gemsa-salida`): `src/index.js` maneja `/api/*` y sirve `public/`.
- **No hay base de datos:** los datos son archivos JSON en `data/` (`entries.json` registros, `users.json` cuentas del personal, `vehicles.json` flota). El Worker los escribe con la API de GitHub, así que **cada registro hace un commit en `main`**. No edites `data/` a mano, y trae siempre lo último de `main` antes de unir.
- En Cloudflare, «Rutas de vigilancia de compilación» excluye `data/**` para que cada registro no vuelva a publicar.
- Roles: **supervisor/admin** (clave `ACCESS_CODE`, ve y maneja todo, papelera y cuentas) y **personal** (solo sus propios registros, sin papelera). Los registros borrados se guardan 30 días.
- Las claves del personal van cifradas con `PASSWORD_KEY`. Si esa llave cambia, las claves guardadas ya no se pueden ver.
- Códigos de unidad: 1 a 4 letras, guion y 1 a 5 números (GD-156, G-101). Horas en formato 24 h (HH:MM).
- La versión vieja de una sola página está en el repo `Gemsa` (`control-salidas.html`).

## Quién es el desarrollador y cómo hablarle
- Es desarrollador (GADR Net) y trabaja solo desde Android con Termux. No tiene PC.
- Háblale en español, corto y sencillo, sin palabras técnicas de más. Primero haz o dile qué hacer; explica solo lo necesario.
- Los textos para sus clientes van claros y sin abreviaturas (nada de «c/u»; escribe «cada una»).

## Reglas de trabajo
- Nunca subas contraseñas, claves, tokens ni cadenas de conexión. Van en los secretos de Cloudflare o en `.dev.vars` (ese archivo no se sube).
- No borres datos reales ni hagas cambios que no se puedan deshacer en la base de datos sin preguntar antes.
- Para detener un proceso, usa su número (`kill <PID>`), nunca `pkill`.
- Antes de subir: no hay build; revisa `src/index.js` con `node --check src/index.js`.
- No hay dependencias que subir; no subas `package-lock.json`.

## Comandos para publicar (Termux)
- Sube tus cambios a la rama que te indique la sesión (`claude/…`), nunca directo a `main`.
- Al terminar, dale al desarrollador este comando completo, con el nombre real de la rama:
  ```
  cd ~/gemsa-Salida && git fetch origin && git checkout main && git pull origin main && git merge --no-edit origin/<rama> && git push origin main
  ```
  (La carpeta en Termux se llama como el repositorio; si no existe, primero `git clone https://github.com/SRALEXANDERGADR/gemsa-Salida.git ~/gemsa-Salida`.)
- Cada push a `main` hace que Cloudflare publique solo.
- Si no puedes subir a GitHub, prepara el cambio como parche (`git diff`) y dale los comandos para aplicarlo en `~/gemsa-Salida`.
- Cuando termines algo importante, anótalo en este archivo para que la próxima sesión lo sepa sin leer el chat viejo.
