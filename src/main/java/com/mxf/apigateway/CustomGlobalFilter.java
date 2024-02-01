package com.mxf.apigateway;

import com.example.apiclientsdk.utils.SignUtils;
import com.mxf.apicommon.model.entity.InterfaceInfo;
import com.mxf.apicommon.model.entity.User;
import com.mxf.apicommon.model.entity.UserInterfaceInfo;
import com.mxf.apicommon.service.InnerInterfaceInfoService;
import com.mxf.apicommon.service.InnerUserInterfaceInfoService;
import com.mxf.apicommon.service.InnerUserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    private static final List<String>IP_WHITE_LIST = Arrays.asList("127.0.0.1");
    private static final String INTERFACE_HOST = "http://localhost:8123";

    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //● 用户发送请求到 API 网关
        //● 请求日志
        ServerHttpRequest request = exchange.getRequest();

        String path = INTERFACE_HOST + request.getPath().value();
        String method = request.getMethod().toString();


        log.info("请求唯一标识"+request.getId());
        log.info("请求路径"+request.getPath().value());
        log.info("请求方法"+request.getMethod());
        log.info("请求参数"+request.getQueryParams());
        log.info("请求来源地址"+request.getRemoteAddress());
        // 获取响应对象
        ServerHttpResponse response = exchange.getResponse();
        //● 黑白名单
        String sourceAddress = request.getRemoteAddress().getHostString();
        if(!IP_WHITE_LIST.contains(sourceAddress)){
            return headNoAuth(response);
        }
        //● 用户鉴权（判断 ak、sk 是否合法）
        // 从请求头中获取参数
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");

        // todo 实际情况应该是去数据库中查是否已分配给用户
        User invokeUser = null;
        try{
            invokeUser = innerUserService.getInvokeUser(accessKey);
        }catch (Exception e){
            log.error("getInvokeUser error",e);
        }
        if (invokeUser == null){
            return headNoAuth(response);
        }



        // 直接校验如果随机数大于1万，则抛出异常，并提示"无权限"
        if (nonce != null && Long.parseLong(nonce) > 10000) {
            return headNoAuth(response);
        }

        final Long FIVE_MINUTES_TIME = 5*60L;
        Long nowtime = System.currentTimeMillis() / 1000;
        if (timestamp != null && (nowtime - new Long(timestamp)) >= FIVE_MINUTES_TIME) {
            return headNoAuth(response);
        }

        // todo 实际情况中是从数据库中查出 secretKey
        String secretKey = invokeUser.getSecretKey();
        String serverSign = SignUtils.genSign(body,secretKey);
        if(sign == null||!sign.equals(serverSign)){
            return headNoAuth(response);
        }



        //● todo 请求的模拟接口是否存在？
        InterfaceInfo interfaceInfo = null;
        try{
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path,method);
        }catch (Exception e){
            log.error("getInterfaceInfo error");
        }
        if (interfaceInfo == null){
            return headNoAuth(response);
        }

        //判断剩余次数
        UserInterfaceInfo userInterfaceInfo = null;
        long interfaceInfoId = interfaceInfo.getId();
        long userId = invokeUser.getId();
        try{
            userInterfaceInfo = innerUserInterfaceInfoService.getUserInterfaceInfo(interfaceInfoId,userId);
        }catch (Exception e){
            log.error("次数不够了");
        }
        if (userInterfaceInfo == null){
            return headNoAuth(response);
        }
        if (userInterfaceInfo.getLeftNum()<=0){
            return headNoAuth(response);
        }




        //● 请求转发，调用模拟接口
        Mono<Void> filter = chain.filter(exchange);
        //● 响应日志
        return handleResponse(exchange,chain,interfaceInfo.getId(),invokeUser.getId());
//        //● 调用失败，返回一个规范的错误码
//        if(response.getStatusCode() == HttpStatus.OK){
//            ;
//        }else{
//            return hacdInvokeError(response);
//        }
    }

    @Override
    public int getOrder() {
        return -1;
    }
    public Mono<Void> headNoAuth(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    public Mono<Void> hacdInvokeError(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }

    /**
     * 处理响应
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain,long interfaceInfoId,long userId) {
        try {
            // 获取原始的响应对象
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 获取数据缓冲工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 获取响应的状态码
            HttpStatus statusCode = originalResponse.getStatusCode();

            // 判断状态码是否为200 OK(按道理来说,现在没有调用,是拿不到响应码的,对这个保持怀疑 沉思.jpg)
            if(statusCode == HttpStatus.OK) {
                // 创建一个装饰后的响应对象(开始穿装备，增强能力)
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

                    // 重写writeWith方法，用于处理响应体的数据
                    // 这段方法就是只要当我们的模拟接口调用完成之后,等它返回结果，
                    // 就会调用writeWith方法,我们就能根据响应结果做一些自己的处理
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        // 判断响应体是否是Flux类型
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 返回一个处理后的响应体
                            // (这里就理解为它在拼接字符串,它把缓冲区的数据取出来，一点一点拼接好)
                            return super.writeWith(fluxBody.map(dataBuffer -> {
                                //● todo 调用成功，接口调用次数 + 1
                                try{
                                    innerUserInterfaceInfoService.invokeCount(interfaceInfoId,userId);
                                }catch (Exception e){
                                    log.error("invokeCount error",e);
                                }



                                // 读取响应体的内容并转换为字节数组
                                byte[] content = new byte[dataBuffer.readableByteCount()];
                                dataBuffer.read(content);
                                DataBufferUtils.release(dataBuffer);//释放掉内存
                                // 构建日志
                                StringBuilder sb2 = new StringBuilder(200);
                                List<Object> rspArgs = new ArrayList<>();
                                rspArgs.add(originalResponse.getStatusCode());
                                //rspArgs.add(requestUrl);
                                String data = new String(content, StandardCharsets.UTF_8);//data
                                sb2.append(data);
                                log.info("响应结果："+data);
                                // 将处理后的内容重新包装成DataBuffer并返回
                                return bufferFactory.wrap(content);
                            }));
                        } else {
                            //● 调用失败，返回一个规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 对于200 OK的请求,将装饰后的响应对象传递给下一个过滤器链,并继续处理(设置repsonse对象为装饰过的)
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            // 对于非200 OK的请求，直接返回，进行降级处理
            return chain.filter(exchange);
        }catch (Exception e){
            // 处理异常情况，记录错误日志
            log.error("gateway log exception.\n" + e);
            return chain.filter(exchange);
        }
    }

}