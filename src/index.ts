import express, { Handler } from 'express';
import passport from 'passport';
import session from 'express-session';
import dotenv from 'dotenv';
import { OIDCStrategy } from './lib/Strategy';

if (!dotenv.config().parsed)
  throw new Error('failed to load secrets from .env');

(async () => {
  const issuerHost = process.env.VIPPS_ISSUER_HOST || '';
  const vippsStrategy = await OIDCStrategy.Create(
    {
      client_id: process.env.VIPPS_CLIENT_ID || '',
      client_secret: process.env.VIPPS_CLIENT_SECRET || '',
      redirect_uris: [process.env.VIPPS_AUTH_REDIRECT || ''],
      response_types: ['code']
    },
    issuerHost
  );

  const app = express();

  passport.use(vippsStrategy);
  passport.serializeUser((user, done) => {
    done(null, user);
  });
  passport.deserializeUser((user, done) => {
    done(null, user);
  });
  app.set('trust proxy', true);
  app.use(
    session({
      secret: 'keyboard cat',
      saveUninitialized: false,
      resave: false,
      cookie: {
        secure: true
      }
    })
  );
  app.use(passport.initialize());
  app.use(passport.session());

  const ensureHTTPS: Handler = (req, res, next) => {
    if (req.headers['x-forwarded-proto'] === 'https') {
      return next();
    }
    return res.redirect('https://' + req.hostname + req.url);
  };

  app.get(
    '/auth',
    ensureHTTPS,
    passport.authenticate('passport-openid-connect')
  );
  app.get(
    '/',
    passport.authenticate('passport-openid-connect', {
      successReturnToOrRedirect: '/hello'
    })
  );
  app.get('/hello', (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res
        .status(200)
        .send('<html><body><a href="/auth">Log in</a></body></html>');
    } else {
      return res
        .status(200)
        .send(
          `<html><body><pre>${JSON.stringify(
            req.user,
            null,
            2
          )}</pre></body></html>`
        );
    }
  });
  app.listen(process.env.PORT || 3000, () => {
    console.log('server listening.');
  });
})();
