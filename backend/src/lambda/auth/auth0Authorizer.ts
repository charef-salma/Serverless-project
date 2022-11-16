import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import Axios from 'axios'
import { JwtPayload } from '../../auth/JwtPayload'

const logs = createLogger('auth');
const jwksUrl = ' https://dev-pmhej6dx.us.auth0.com/.well-known/jwks.json';

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {

  logs.info('To authorize user', event.authorizationToken )

  try {

    const jwtToken = await verifyToken(event.authorizationToken)

    logs.info('User authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {

    logs.error('User unauthorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  try {

    const token = getToken(authHeader)
    const res = await Axios.get(jwksUrl);

    // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
    const pemData = res['data']['keys'][0]['x5c'][0]
    const cert = `-----BEGIN CERTIFICATE-----\n${pemData}\n-----END CERTIFICATE-----`

    return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
  } catch (err) {
    logs.error('Fail to authenticate', err)
  }
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('Failed: no authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Authentication header is invalid')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}

