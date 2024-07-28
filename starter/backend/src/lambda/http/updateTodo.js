
import middy from "@middy/core";
import cors from '@middy/http-cors'
import httpErrorHandler from "@middy/http-error-handler";
import {createLogger} from '../../utils/logger.mjs'
import {updateTodo} from "../../bussinessLogic/todos.mjs";
import {getUserId} from "../utils.mjs";

const logger = createLogger('update TODO')

export const handler = middy()
  .use(httpErrorHandler())
  .use(cors({
    credentials: true
  }))
  .handler(async (event) => {

  // TODO: Update a TODO item with the provided id using values in the "updatedTodo" object
  const updatedTodo = JSON.parse(event.body)
  const todoId = event.pathParameters.todoId
  const userId = getUserId(event)

  logger.info(`Updating Todo item ${JSON.stringify(updatedTodo, null, 2)}, id: ${todoId}`)


  await updateTodo(userId, todoId, updatedTodo);

  return {
    statusCode: 204,
  };
})
