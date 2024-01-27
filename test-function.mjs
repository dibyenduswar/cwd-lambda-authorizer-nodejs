export const handler = async (event, context) => {
  const response = {
    statusCode: 200,
    body: JSON.stringify(event.requestContext.authorizer),  // passed auth data from lambda authorizer
  };
  return response;
};
