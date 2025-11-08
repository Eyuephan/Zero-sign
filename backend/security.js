import helmet from "helmet";
import compression from "compression";

export default function harden(app){
  app.disable("x-powered-by");
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(compression());
}
