//
//  ========================================================================
//  Copyright (c) 1995-2017 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.server.session;

import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.toolchain.test.FS;
import org.eclipse.jetty.toolchain.test.MavenTestingUtils;
import org.eclipse.jetty.util.IO;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class HashSessionManagerTest
{
    @Test
    public void testDangerousSessionIdRemoval() throws Exception
    {
        final HashSessionManager manager = new HashSessionManager();
        manager.setDeleteUnrestorableSessions(true);
        manager.setLazyLoad(true);
        File testDir = MavenTestingUtils.getTargetTestingDir("hashes");
        testDir.mkdirs();
        manager.setStoreDirectory(testDir);

        MavenTestingUtils.getTargetFile("dangerFile.session").createNewFile();
        
        Assert.assertTrue("File should exist!", MavenTestingUtils.getTargetFile("dangerFile.session").exists());

        manager.getSession("../../dangerFile.session");
        
        Assert.assertTrue("File should exist!", MavenTestingUtils.getTargetFile("dangerFile.session").exists());

    }
    
   @Test
    public void testValidSessionIdRemoval() throws Exception
    {
        final HashSessionManager manager = new HashSessionManager();
        manager.setDeleteUnrestorableSessions(true);
        manager.setLazyLoad(true);
        File testDir = MavenTestingUtils.getTargetTestingDir("hashes");
        FS.ensureEmpty(testDir);
        
        manager.setStoreDirectory(testDir);

        Assert.assertTrue(new File(testDir, "validFile.session").createNewFile());
        
        Assert.assertTrue("File should exist!", new File(testDir, "validFile.session").exists());
       
        manager.getSession("validFile.session");

        Assert.assertTrue("File shouldn't exist!", !new File(testDir,"validFile.session").exists());
    }
    
    @Test
    public void testHashSession() throws Exception
    {
        File testDir = MavenTestingUtils.getTargetTestingDir("saved");
        IO.delete(testDir);
        testDir.mkdirs();
        
        Server server = new Server();
        SessionHandler handler = new SessionHandler();
        handler.setServer(server);
        HashSessionManager manager = new HashSessionManager();
        manager.setStoreDirectory(testDir);
        manager.setMaxInactiveInterval(5);
        Assert.assertTrue(testDir.exists());
        Assert.assertTrue(testDir.canWrite());
        handler.setSessionManager(manager);
        
        AbstractSessionIdManager idManager = new HashSessionIdManager();
        idManager.setWorkerName("foo");
        manager.setSessionIdManager(idManager);
        server.setSessionIdManager(idManager);
        
        server.start();
        manager.start();
        
        HashedSession session = (HashedSession)manager.newHttpSession(new Request(null, null));
        String sessionId = session.getId();
        
        session.setAttribute("one", new Integer(1));
        session.setAttribute("two", new Integer(2));    
        
        //stop will persist sessions
        manager.setMaxInactiveInterval(30); // change max inactive interval for *new* sessions
        manager.stop();
        
        Assert.assertTrue("File should exist!", new File(testDir, session.getId()).exists());
        
        //start will restore sessions
        manager.start();
        
        HashedSession restoredSession = (HashedSession)manager.getSession(sessionId);
        Assert.assertNotNull(restoredSession);
        
        Object o = restoredSession.getAttribute("one");
        Assert.assertNotNull(o);
        
        Assert.assertEquals(1, ((Integer)o).intValue());
        Assert.assertEquals(5, restoredSession.getMaxInactiveInterval());     
        
        server.stop();
    }

    private static HashSessionManager newStartedManager(Server server, HttpSessionListener... listeners) throws Exception
    {
        SessionHandler handler = new SessionHandler();
        handler.setServer(server);
        HashSessionManager manager = new HashSessionManager();
        manager.setMaxInactiveInterval(5);
        handler.setSessionManager(manager);

        AbstractSessionIdManager idManager = new HashSessionIdManager();
        idManager.setWorkerName("foo");
        manager.setSessionIdManager(idManager);
        server.setSessionIdManager(idManager);

        for (HttpSessionListener listener : listeners)
            manager.addEventListener(listener);

        server.start();
        manager.start();
        return manager;
    }

    private static HttpSessionListener throwingListener(final boolean onCreate, final boolean onDestroy)
    {
        return new HttpSessionListener()
        {
            @Override
            public void sessionCreated(HttpSessionEvent se)
            {
                if (onCreate)
                    throw new RuntimeException("Intentional exception from sessionCreated");
            }

            @Override
            public void sessionDestroyed(HttpSessionEvent se)
            {
                if (onDestroy)
                    throw new RuntimeException("Intentional exception from sessionDestroyed");
            }
        };
    }

    private static HttpSessionListener countingListener(final AtomicInteger created, final AtomicInteger destroyed)
    {
        return new HttpSessionListener()
        {
            @Override
            public void sessionCreated(HttpSessionEvent se)
            {
                created.incrementAndGet();
            }

            @Override
            public void sessionDestroyed(HttpSessionEvent se)
            {
                destroyed.incrementAndGet();
            }
        };
    }

    private static void assertInvalidated(HashSessionManager manager, AbstractSession session, String sessionId)
    {
        Assert.assertFalse("Session should be invalid", session.isValid());
        try
        {
            session.getAttribute("secret");
            Assert.fail("Session attributes should not be accessible after invalidation");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        Assert.assertNull("Session should be removed from manager", manager.getSession(sessionId));
    }

    @Test
    public void testInvalidateWithThrowingDestroyListener() throws Exception
    {
        Server server = new Server();
        AtomicInteger created = new AtomicInteger();
        AtomicInteger destroyed = new AtomicInteger();
        // destroy listeners are invoked in reverse order, so the throwing listener runs first
        HashSessionManager manager = newStartedManager(server,
                countingListener(created, destroyed),
                throwingListener(false, true));
        try
        {
            AbstractSession session = (AbstractSession)manager.newHttpSession(new Request(null, null));
            String sessionId = session.getClusterId();
            session.setAttribute("secret", "value");
            Assert.assertEquals(1, created.get());

            // must not propagate the listener exception and must still invalidate the session
            session.invalidate();

            Assert.assertEquals("Remaining destroy listeners must still be called", 1, destroyed.get());
            assertInvalidated(manager, session, sessionId);
        }
        finally
        {
            manager.stop();
            server.stop();
        }
    }

    @Test
    public void testTimeoutWithThrowingDestroyListener() throws Exception
    {
        Server server = new Server();
        AtomicInteger created = new AtomicInteger();
        AtomicInteger destroyed = new AtomicInteger();
        HashSessionManager manager = newStartedManager(server,
                countingListener(created, destroyed),
                throwingListener(false, true));
        try
        {
            AbstractSession session = (AbstractSession)manager.newHttpSession(new Request(null, null));
            String sessionId = session.getClusterId();
            session.setAttribute("secret", "value");
            // new sessions start with one outstanding request; complete it so timeout invalidates immediately
            manager.complete(session);

            session.timeout();

            Assert.assertEquals("Remaining destroy listeners must still be called", 1, destroyed.get());
            assertInvalidated(manager, session, sessionId);
        }
        finally
        {
            manager.stop();
            server.stop();
        }
    }

    @Test
    public void testThrowingCreateListener() throws Exception
    {
        Server server = new Server();
        AtomicInteger created = new AtomicInteger();
        AtomicInteger destroyed = new AtomicInteger();
        HashSessionManager manager = newStartedManager(server,
                throwingListener(true, false),
                countingListener(created, destroyed));
        try
        {
            AbstractSession session = (AbstractSession)manager.newHttpSession(new Request(null, null));
            Assert.assertNotNull(session);
            Assert.assertEquals("Remaining create listeners must still be called", 1, created.get());
            Assert.assertTrue(session.isValid());

            session.invalidate();
            Assert.assertEquals(1, destroyed.get());
            Assert.assertFalse(session.isValid());
        }
        finally
        {
            manager.stop();
            server.stop();
        }
    }
}
