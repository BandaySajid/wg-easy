"use strict";

const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const { createServer } = require("node:http");
const { stat, readFile } = require("node:fs/promises");
const { resolve, sep } = require("node:path");
const fs = require("fs/promises");
const path = require("node:path");
const config = require("../config.js");

const expressSession = require("express-session");
const debug = require("debug")("Server");
const nodemailer = require("nodemailer");

const {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  fromNodeMiddleware,
  getRouterParam,
  toNodeListener,
  readBody,
  setHeader,
  serveStatic,
} = require("h3");

const WireGuard = require("../services/WireGuard");

const {
  PORT,
  WEBUI_HOST,
  RELEASE,
  PASSWORD,
  PASSWORD_HASH,
  LANG,
  UI_TRAFFIC_STATS,
  UI_CHART_TYPE,
} = require("../config");

const requiresPassword = !!PASSWORD || !!PASSWORD_HASH;

/**
 * Checks if `password` matches the PASSWORD_HASH.
 *
 * For backward compatibility it also allows `password` to match the clear text PASSWORD,
 * but only if no PASSWORD_HASH is provided.
 *
 * If both enviornment variables are not set, the password is always invalid.
 *
 * @param {string} password String to test
 * @returns {boolean} true if matching environment, otherwise false
 */
const isPasswordValid = (password) => {
  if (typeof password !== "string") {
    return false;
  }

  if (PASSWORD_HASH) {
    return bcrypt.compareSync(password, PASSWORD_HASH);
  }
  if (PASSWORD) {
    return password === PASSWORD;
  }

  return false;
};

async function getClientConfig(clientId) {
  const client = await WireGuard.getClient({ clientId });
  const clientConfig = await WireGuard.getClientConfiguration({ clientId });
  const configName = client.name
    .replace(/[^a-zA-Z0-9_=+.-]/g, "-")
    .replace(/(-{2,}|-$)/g, "-")
    .replace(/-$/, "")
    .substring(0, 32);
  return { configName, clientConfig };
}

const ePath = path.resolve("/etc/wireguard/emails.json");

async function getClientsEmails() {
  // path for the container, /app
  // path for dev, /src
  let emails = await fs.readFile(ePath, "utf8");

  return JSON.parse(emails);
}

async function addClientsEmails(newEmails) {
  const currentEmails = await getClientsEmails();

  const finalJsonEmails = currentEmails.filter((c) => c).concat(newEmails);

  await fs.writeFile(ePath, JSON.stringify(finalJsonEmails));
}

async function deleteClientsEmails(emails) {
  const currentEmails = await getClientsEmails();

  const finalJsonEmails = currentEmails.filter((email) => {
    if (email) {
      for (const e of emails) {
        if (e !== email) {
          return email;
        }
      }
    }
  });

  await fs.writeFile(ePath, JSON.stringify(finalJsonEmails));
}

function setupMailer() {
  if (config.EMAIL_CLIENT === 1) {
    try {
      const transporter = nodemailer.createTransport({
        host: config.SMTP_HOST,
        port: config.SMTP_PORT,
        secure: config.SMTP_IS_SECURE === 1 ? true : false, // Use `true` for port 465, `false` for all other ports
        auth: {
          user: config.SMTP_EMAIL,
          pass: config.SMTP_PASSWORD,
        },
      });

      return transporter;
    } catch (err) {
      return null;
    }
  }
}

async function sendEmail(
  transporter,
  clients,
  configName,
  clientConfig,
  imgPath,
) {
  const client = clients[0];
  const html = `<img src="cid:qr@wg.config_qr"/>`;
  await transporter.sendMail({
    from: `"${config.SMTP_USER}" <${config.SMTP_EMAIL}>`, // sender address
    to: `${client.email}`, // list of receivers
    subject: config.EMAIL_SUBJECT, // Subject line
    text: config.EMAIL_TEXT, // plain text body
    html, // html body
    attachments: [
      {
        filename: configName,
        content: clientConfig,
        contentType: "text/plain",
      },
      {
        filename: "qr.png",
        path: imgPath,
        cid: "qr@wg.config_qr",
      },
    ],
  });

  await fs.rm(imgPath);
}

module.exports = class Server {
  constructor() {
    const app = createApp();
    this.app = app;

    this.transporter = setupMailer();

    app.use(
      fromNodeMiddleware(
        expressSession({
          secret: crypto.randomBytes(256).toString("hex"),
          resave: true,
          saveUninitialized: true,
        }),
      ),
    );

    const router = createRouter();
    app.use(router);

    router
      .get(
        "/api/release",
        defineEventHandler((event) => {
          setHeader(event, "Content-Type", "application/json");
          return RELEASE;
        }),
      )

      .get(
        "/api/lang",
        defineEventHandler((event) => {
          setHeader(event, "Content-Type", "application/json");
          return `"${LANG}"`;
        }),
      )

      .get(
        "/api/ui-traffic-stats",
        defineEventHandler((event) => {
          setHeader(event, "Content-Type", "application/json");
          return `"${UI_TRAFFIC_STATS}"`;
        }),
      )

      .get(
        "/api/ui-chart-type",
        defineEventHandler((event) => {
          setHeader(event, "Content-Type", "application/json");
          return `"${UI_CHART_TYPE}"`;
        }),
      )

      // Authentication
      .get(
        "/api/session",
        defineEventHandler((event) => {
          const authenticated = requiresPassword
            ? !!(event.node.req.session && event.node.req.session.authenticated)
            : true;

          return {
            requiresPassword,
            authenticated,
          };
        }),
      )
      .post(
        "/api/session",
        defineEventHandler(async (event) => {
          const { password } = await readBody(event);

          if (!requiresPassword) {
            // if no password is required, the API should never be called.
            // Do not automatically authenticate the user.
            throw createError({
              status: 401,
              message: "Invalid state",
            });
          }

          if (!isPasswordValid(password)) {
            throw createError({
              status: 401,
              message: "Incorrect Password",
            });
          }

          event.node.req.session.authenticated = true;
          event.node.req.session.save();

          debug(`New Session: ${event.node.req.session.id}`);

          return { success: true };
        }),
      )
      .get(
        "/api/wireguard/emails",
        defineEventHandler(async (_) => {
          try {
            const emails = await getClientsEmails();
            return emails;
          } catch (err) {
            throw createError({
              status: 500,
              message: "internal server error",
            });
          }
        }),
      )
      .post(
        "/api/wireguard/emails",
        defineEventHandler(async (event) => {
          try {
            let { clients } = await readBody(event);

            clients = clients.filter((c) => c);

            await addClientsEmails(clients);
            return { success: true };
          } catch (err) {
            throw createError({
              status: 500,
              message: "internal server error",
            });
          }
        }),
      )
      .delete(
        "/api/wireguard/emails",
        defineEventHandler(async (event) => {
          try {
            const { clients } = await readBody(event);

            await deleteClientsEmails(clients);
            return { success: true };
          } catch (err) {
            throw createError({
              status: 500,
              message: "internal server error",
            });
          }
        }),
      )

      .post(
        "/api/wireguard/emails/send",
        defineEventHandler(async (event) => {
          try {
            const { clients, clientId } = await readBody(event);
            const { clientConfig, configName } =
              await getClientConfig(clientId);

            const { img } = await WireGuard.getClientQRCodeSVG({ clientId });

            if (!this.transporter) {
              throw createError({
                status: 500,
                message: "smtp configuration error",
              });
            }

            await sendEmail(
              this.transporter,
              clients,
              configName,
              clientConfig,
              img, //img path
            );
            return { success: true };
          } catch (err) {
            console.log(err);
            throw createError({
              status: 500,
              message: "internal server error",
            });
          }
        }),
      );

    // WireGuard
    app.use(
      fromNodeMiddleware((req, res, next) => {
        if (!requiresPassword || !req.url.startsWith("/api/")) {
          return next();
        }

        if (req.session && req.session.authenticated) {
          return next();
        }

        if (req.url.startsWith("/api/") && req.headers["authorization"]) {
          if (isPasswordValid(req.headers["authorization"])) {
            return next();
          }
          return res.status(401).json({
            error: "Incorrect Password",
          });
        }

        return res.status(401).json({
          error: "Not Logged In",
        });
      }),
    );

    const router2 = createRouter();
    app.use(router2);

    router2
      .delete(
        "/api/session",
        defineEventHandler((event) => {
          const sessionId = event.node.req.session.id;

          event.node.req.session.destroy();

          debug(`Deleted Session: ${sessionId}`);
          return { success: true };
        }),
      )
      .get(
        "/api/wireguard/client",
        defineEventHandler(() => {
          return WireGuard.getClients();
        }),
      )
      .get(
        "/api/wireguard/client/:clientId/qrcode.svg",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          const { svg } = await WireGuard.getClientQRCodeSVG({ clientId });
          setHeader(event, "Content-Type", "image/svg+xml");
          return svg;
        }),
      )
      .get(
        "/api/wireguard/client/:clientId/configuration",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          const { configName, clientConfig } = await getClientConfig(clientId);

          setHeader(
            event,
            "Content-Disposition",
            `attachment; filename="${configName || clientId}.conf"`,
          );
          setHeader(event, "Content-Type", "text/plain");
          return clientConfig;
        }),
      )
      .post(
        "/api/wireguard/client",
        defineEventHandler(async (event) => {
          const { name } = await readBody(event);
          await WireGuard.createClient({ name });
          return { success: true };
        }),
      )
      .delete(
        "/api/wireguard/client/:clientId",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          await WireGuard.deleteClient({ clientId });
          return { success: true };
        }),
      )
      .post(
        "/api/wireguard/client/:clientId/enable",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          if (
            clientId === "__proto__" ||
            clientId === "constructor" ||
            clientId === "prototype"
          ) {
            throw createError({ status: 403 });
          }
          await WireGuard.enableClient({ clientId });
          return { success: true };
        }),
      )
      .post(
        "/api/wireguard/client/:clientId/disable",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          if (
            clientId === "__proto__" ||
            clientId === "constructor" ||
            clientId === "prototype"
          ) {
            throw createError({ status: 403 });
          }
          await WireGuard.disableClient({ clientId });
          return { success: true };
        }),
      )
      .put(
        "/api/wireguard/client/:clientId/name",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          if (
            clientId === "__proto__" ||
            clientId === "constructor" ||
            clientId === "prototype"
          ) {
            throw createError({ status: 403 });
          }
          const { name } = await readBody(event);
          await WireGuard.updateClientName({ clientId, name });
          return { success: true };
        }),
      )
      .put(
        "/api/wireguard/client/:clientId/address",
        defineEventHandler(async (event) => {
          const clientId = getRouterParam(event, "clientId");
          if (
            clientId === "__proto__" ||
            clientId === "constructor" ||
            clientId === "prototype"
          ) {
            throw createError({ status: 403 });
          }
          const { address } = await readBody(event);
          await WireGuard.updateClientAddress({ clientId, address });
          return { success: true };
        }),
      );

    const safePathJoin = (base, target) => {
      // Manage web root (edge case)
      if (target === "/") {
        return `${base}${sep}`;
      }

      // Prepend './' to prevent absolute paths
      const targetPath = `.${sep}${target}`;

      // Resolve the absolute path
      const resolvedPath = resolve(base, targetPath);

      // Check if resolvedPath is a subpath of base
      if (resolvedPath.startsWith(`${base}${sep}`)) {
        return resolvedPath;
      }

      throw createError({
        status: 400,
        message: "Bad Request",
      });
    };

    // Static assets
    const publicDir = "/app/www";
    app.use(
      defineEventHandler((event) => {
        return serveStatic(event, {
          getContents: (id) => {
            return readFile(safePathJoin(publicDir, id));
          },
          getMeta: async (id) => {
            const filePath = safePathJoin(publicDir, id);

            const stats = await stat(filePath).catch(() => {});
            if (!stats || !stats.isFile()) {
              return;
            }

            if (id.endsWith(".html"))
              setHeader(event, "Content-Type", "text/html");
            if (id.endsWith(".js"))
              setHeader(event, "Content-Type", "application/javascript");
            if (id.endsWith(".json"))
              setHeader(event, "Content-Type", "application/json");
            if (id.endsWith(".css"))
              setHeader(event, "Content-Type", "text/css");
            if (id.endsWith(".png"))
              setHeader(event, "Content-Type", "image/png");

            return {
              size: stats.size,
              mtime: stats.mtimeMs,
            };
          },
        });
      }),
    );

    createServer(toNodeListener(app)).listen(PORT, WEBUI_HOST);
    debug(`Listening on http://${WEBUI_HOST}:${PORT}`);
  }
};
