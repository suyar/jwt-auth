<?php
/**
 * Created by PhpStorm.
 * User: liyuzhao
 * Date: 2019-08-01
 * Time: 22:32
 */
namespace Trrtly\JWTAuth\Middleware;

use Hyperf\HttpServer\Contract\ResponseInterface as HttpResponse;
use Trrtly\JWTAuth\Exception\JWTException;
use Trrtly\JWTAuth\Util\JWTUtil;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Trrtly\JWTAuth\JWT;
use Trrtly\JWTAuth\Exception\TokenValidException;

/**
 * jwt token 校验的中间件，校验场景是否一致
 * Class JWTAuthApplicationSceneMiddleware
 * @package Trrtly\JWTAuth\Middleware
 */
class JWTAuthApplicationSceneMiddleware implements MiddlewareInterface
{
    /**
     * @var HttpResponse
     */
    protected $response;

    protected $jwt;

    public function __construct(HttpResponse $response, JWT $jwt)
    {
        $this->response = $response;
        $this->jwt = $jwt;
    }

    /**
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \Throwable
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // 判断是否为noCheckRoute
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();
        if ($this->jwt->matchRoute('application', $method, $path)) {
            return $handler->handle($request);
        }

        $token = $request->getHeaderLine('Authorization') ?? '';
        if ($token == "") {
            throw new JWTException('Missing token', 400);
        }
        $token = JWTUtil::handleToken($token);
        if ($token !== false && $this->jwt->verifyTokenAndScene('application', $token)) {
            return $handler->handle($request);
        }

        throw new TokenValidException('Token authentication does not pass', 400);
    }
}
