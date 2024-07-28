import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import { createLogger } from '../../utils/logger.mjs'
import { createTodo } from '../../bussinessLogic/todos.mjs'
import { getUserId } from '../utils.mjs'

const logger = createLogger('createTodo');

export const handler = middy()
  .use(httpErrorHandler())
  .use(cors({
    credentials: true
  }))
  .handler(async (event) => {
    // TODO: Implement creating a new TODO item
    const userId = getUserId(event);
    logger.info(`Creating TODO item: ${JSON.stringify(event)}`);

    const newTodo = JSON.parse(event.body);
    const item = await createTodo(newTodo, userId);

    logger.info(`Todo item created: ${JSON.stringify(item)}`);

    return  {
      statusCode: 201, body: JSON.stringify({
        item
      })
    }
  })

