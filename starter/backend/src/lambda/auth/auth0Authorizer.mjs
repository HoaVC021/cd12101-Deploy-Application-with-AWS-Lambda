import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const certificate =`-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJG+qFMm+Krp0dMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi16amtydGNuNjMzbjd2cDYzLnVzLmF1dGgwLmNvbTAeFw0yNDA3MjQw
NjQzNTlaFw0zODA0MDIwNjQzNTlaMCwxKjAoBgNVBAMTIWRldi16amtydGNuNjMz
bjd2cDYzLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAK81qWqpTwzOUC9uYDAfMIPNHSXnZ+z9PX/WmvgdXwuZI3u/0yoWQrnMZyZC
LOV6IIbux3RoY7OzNsGnUVC5h/HZVwmsbuCGLxoxq2NsYjyXL7tnM/ZHSMEulb2i
AQ6vHnXX54o2R4sxOFuCg+IkTC8lnD5SbmE6B0bDgUIP/YJXkm/LYRuRU58LKo3o
VcdgGyYkXMMmBKaOjAO1NsPG2ky6hz/Elay5tj6Y4o4R0MvlThZJC/WSB7Rm9uVe
IxyocpUSWYTBKhEJ82lJ5IDnzUWb+NJpPmaNfI8v2xgw+j56eDLePM2PnErz5/qB
/GyBIfkwxzmIhgUUDIVAH82JQ0cCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUEe3r8f5rrqOC6TKLT9Lu/k5Y1jYwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBlFTLwXJBxw1fTuwEtvLp+3eiqtjwcRmtimhnAbj7A
fdJrzvAdaS4QGph6Qtc2XgrDNiLCP08pyZh6dyovpedCvCBl6rieHpCqD62NgYNY
Km5QF60lCdTYG8aPOm4HHn647SS8IAUeLRqeR9iWwyfmgM/lXcaEL+Dj9oLVs3sr
G3FpM7jNZ6CHWZpWhS/c6SNLk76znpsZLq86KndfC/G8U1N1mdEBtIs/V6ScMzhm
X1/tsuZGODhdh1EHf22VXCa3yKExB423+R/qLQuSVuh+gsbUBy7Szc4a2NQv+vI/
8UxaIW9cKFSWDjYIRXoygzZrz4Y05zl4AhyE9QYuGVfN
-----END CERTIFICATE-----`
export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

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
    logger.error('User not authorized', { error: e.message })

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

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  const jwt = jsonwebtoken.decode(token, { complete: true })
  // TODO: Implement token verification -> done
  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
