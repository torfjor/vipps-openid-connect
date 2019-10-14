import { Issuer, generators, Client, ResponseType } from 'openid-client';
import { Strategy } from 'passport';
import { Request } from 'express';

interface IOIDCConfig {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  response_types: ResponseType[];
}

export class OIDCStrategy extends Strategy {
  name: string;

  constructor(private client: Client) {
    super();
    this.name = 'passport-openid-connect';
  }

  /**
   * static Create
   */
  public static Create = async (config: IOIDCConfig, issuerHost: string) => {
    const issuer = await Issuer.discover(issuerHost);
    const client = new issuer.Client({
      client_secret: config.client_secret,
      client_id: config.client_id,
      response_types: config.response_types,
      redirect_uris: config.redirect_uris
    });

    return new OIDCStrategy(client);
  };

  authenticate(req: Request, opts: any) {
    if (req.query['code']) {
      return this.callback(req, opts);
    }
    if (!req.session) {
      return this.fail('No session');
    }
    const state = generators.state();
    req.session.vipps_state = state;
    return this.redirect(
      this.client.authorizationUrl({
        scope: 'openid name email birthDate phoneNumber address',
        state
      })
    );
  }

  async callback(req: Request, opts: any) {
    const params = this.client.callbackParams(req);
    if (!req.session || !req.session.vipps_state) {
      return this.fail('Broken / no session');
    }
    try {
      const tokenSet = await this.client.callback(
        this.client.metadata.redirect_uris![0],
        params,
        { state: req.session.vipps_state }
      );
      const user = await this.client.userinfo(tokenSet);
      return this.success(user);
    } catch (error) {
      console.error(error);
      return this.fail(error.message);
    }
  }
}
