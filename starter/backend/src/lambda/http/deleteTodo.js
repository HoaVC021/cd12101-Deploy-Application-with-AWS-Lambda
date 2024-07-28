import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import {createLogger} from '../../utils/logger.mjs'
import {deleteTodo} from '../../bussinessLogic/todos.mjs'
import {getUserId} from "../utils.mjs";

const logger = createLogger('delete TODO')

export const handler = middy()
  .use(httpErrorHandler())
  .use(cors({
    credentials: true
  }))
  .handler(async (event) =>  {
  // TODO: Remove a TODO item by id
  const todoId = event.pathParameters.todoId

  logger.info(`Deleting Todo item ${todoId}`)
  const userId = getUserId(event)

  await deleteTodo(userId, todoId)

  return {
    statusCode: 204
  }
})

