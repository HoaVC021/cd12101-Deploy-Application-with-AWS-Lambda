
import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import {getByUserId} from '../../bussinessLogic/todos.mjs'
import {getUserId} from '../utils.mjs'
import {createLogger} from '../../utils/logger.mjs'

const logger = createLogger("get TODO")

export const handler = middy()
  .use(httpErrorHandler())
  .use(cors({
    credentials: true
  }))
  .handler(async(event) => {
  // TODO: Get all TODO items for a current user
  logger.info(`Getting all Todos ${JSON.stringify(event)}`)

  const userId = getUserId(event)

  const items = (await getByUserId(userId))

  return {
    statusCode: 200, body: JSON.stringify({
      items
    })
  }
})
