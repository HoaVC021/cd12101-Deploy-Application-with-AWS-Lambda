import * as uuid from 'uuid'
import {TodosAccess} from "../dataLayer/todosAccess.mjs";
import {createLogger} from "../utils/logger.mjs";

const logger = createLogger('businessLogic')

const todosAccess = new TodosAccess();

export async function createTodo(createTodoRequest, userId) {
  const todoId = uuid.v4()
  logger.info(`Creating todo item ${todoId} for ${userId} `)

  return await todosAccess.create({
    todoId, userId, createdAt: new Date().toISOString(), done: false, ...createTodoRequest
  });
}

export async function deleteTodo(userId, todoId) {
    logger.info(`Deleting todo item ${todoId} for ${userId}`)
    return await todosAccess.delete(userId, todoId);
  }

export async function updateTodo(userId, todoId, updateTodoRequest) {
  logger.info(`Updating todo item ${todoId} for ${userId}  request ${JSON.stringify(updateTodoRequest, null, 2)}`)
  return await todosAccess.update(userId, todoId, {...updateTodoRequest});
}

export async function setAttachmentUrl(userId, todoId, image, attachmentUrl) {
  logger.info(`Setting attachmentUrl ${attachmentUrl} for ${userId} with todo item ${todoId} `)
  return await todosAccess.setAttachmentUrl(userId, todoId, image, attachmentUrl);
}

export async function getByUserId(userId) {
    logger.info(`Getting user by Id ${userId}`)
    return todosAccess.getByUserId(userId);
  }