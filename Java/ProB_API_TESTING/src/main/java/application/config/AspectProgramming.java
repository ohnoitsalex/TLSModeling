package application.config;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.After;

@Aspect
public class AspectProgramming {

    // Pointcut targeting a specific method in the Maven library
//    @Before("execution(* org.bouncycastle.tls.DefaultTlsServer.getServerExtensions(..))")
//    public void logBeforeGetServerExtensions(JoinPoint joinPoint) {
//        System.out.println("Intercepted method: " + joinPoint.getSignature());
//        System.out.println("Called by: " + joinPoint.getSourceLocation());
//    }
//
//    // Optional: Log after method execution
//    @After("execution(* org.bouncycastle.tls.DefaultTlsServer.getServerExtensions(..))")
//    public void logAfterGetServerExtensions(JoinPoint joinPoint) {
//        System.out.println("Finished executing method: " + joinPoint.getSignature());
//    }

    @Before("execution(* org.bouncycastle.tls.TlsClientProtocol.sendClientHelloMessage(..))")
    public void logBeforeClientHello(JoinPoint joinPoint){
        System.out.println("Intercepted method: " + joinPoint.getSignature());
        System.out.println("Called by: " + joinPoint.getSourceLocation());
    }

    @After("execution(* org.bouncycastle.tls.TlsClientProtocol.sendClientHelloMessage(..))")
    public void logAfterClientHello(JoinPoint joinPoint){
        System.out.println("Finished executing method: " + joinPoint.getSignature());
    }
}
