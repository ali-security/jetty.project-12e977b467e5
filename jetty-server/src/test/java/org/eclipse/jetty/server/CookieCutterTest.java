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

package org.eclipse.jetty.server;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.Cookie;

import org.junit.Test;

public class CookieCutterTest
{
    private static Cookie[] parseCookieHeaders(String... headers)
    {
        CookieCutter cutter = new CookieCutter();
        for (String header : headers)
        {
            cutter.addCookieField(header);
        }
        return cutter.getCookies();
    }

    private static List<String> toNameValues(Cookie[] cookies)
    {
        List<String> nameValues = new ArrayList<>();
        for (Cookie cookie : cookies)
        {
            nameValues.add(cookie.getName() + "=" + cookie.getValue());
        }
        return nameValues;
    }

    private static void assertCookies(String[][] data)
    {
        for (String[] row : data)
        {
            String input = row[0];
            List<String> expected = Arrays.asList(row).subList(1, row.length);
            Cookie[] cookies = parseCookieHeaders(input);
            assertEquals("Cookies of <" + input + ">", expected, toNameValues(cookies));
        }
    }

    /**
     * CVE-2023-26049: a ';' inside a quoted value must not let that cookie absorb the cookies that follow it.
     */
    @Test
    public void testQuotedSemicolonRejected()
    {
        String[][] data = new String[][]
        {
            {"A=\"1; B=2\"; C=3", "C=3"},
            {"A=\"1;B=2\"; C=3", "C=3"},
            {"A=\"1\\; B=2\"; C=3", "C=3"},
            {"A=\"1; B=2\"", },
            {"SESSION=1234; other=\"quoted=;HttpOnly_cookie=secret\"", "SESSION=1234"},
            {"SESSION=1234; other=\"quoted=; HttpOnly_cookie=secret\"; C=3", "SESSION=1234", "C=3"},
            {"DISPLAY_LANGUAGE=\"b; JSESSIONID=1337; c=d\"; JSESSIONID=abc", "JSESSIONID=abc"},
            {"\"A; B\"=1; C=3", "C=3"},
            {"A=\"1; B=2; C=3"},
        };
        assertCookies(data);
    }

    /**
     * The handling of cookies without a ';' inside a quoted value is unchanged.
     */
    @Test
    public void testUnchangedCookies()
    {
        String[][] data = new String[][]
        {
            {"A=1; B=2; C=3", "A=1", "B=2", "C=3"},
            {"A=\"1\"; B=2; C=3", "A=1", "B=2", "C=3"},
            {"A=\"1\"; B=\"2\"; C=\"3\"", "A=1", "B=2", "C=3"},
            {"A=\"1 B=2\"; C=3", "A=1 B=2", "C=3"},
            {"A=\"1,\"; B=2; C=3", "A=1,", "B=2", "C=3"},
            {"A=\"\\1\"; B=2; C=3", "A=1", "B=2", "C=3"},
            {"A=\"1\"x; B=2\"; C=3", "A=\"1\"x", "B=2\"", "C=3"},
            {"A=1;B=2;C=3", "A=1", "B=2", "C=3"},
            {"A=1\\; B=2", "A=1\\", "B=2"},
            {"x=\"abc"},
        };
        assertCookies(data);
    }

    /**
     * Only the cookie with the ';' in its quoted value is dropped, also when the cookies come in separate fields.
     */
    @Test
    public void testRejectionIsLimitedToOneCookie()
    {
        Cookie[] cookies = parseCookieHeaders("A=\"1; B=2\"", "C=3", "D=\"4\"");
        assertEquals(Arrays.asList("C=3", "D=4"), toNameValues(cookies));

        cookies = parseCookieHeaders("A=0; B=\"1; C=2\"; D=\"3\"; E=4");
        assertEquals(Arrays.asList("A=0", "D=3", "E=4"), toNameValues(cookies));
    }

    /**
     * The attributes of a rejected cookie are not applied to the previous cookie,
     * and an attribute whose quoted value holds a ';' is ignored.
     */
    @Test
    public void testRejectedCookieAttributes()
    {
        Cookie[] cookies = parseCookieHeaders("$Version=1; X=0; A=\"1; B=2\"; $Path=/a; $Domain=a.com; C=3; $Path=/c");
        assertEquals(Arrays.asList("X=0", "C=3"), toNameValues(cookies));
        assertThat("X.path", cookies[0].getPath(), nullValue());
        assertThat("X.domain", cookies[0].getDomain(), nullValue());
        assertEquals("X.version", 1, cookies[0].getVersion());
        assertEquals("C.path", "/c", cookies[1].getPath());
        assertEquals("C.version", 1, cookies[1].getVersion());

        cookies = parseCookieHeaders("$Version=1; A=0; $Path=\"/a; B=2\"; $Domain=a.com");
        assertEquals(Arrays.asList("A=0"), toNameValues(cookies));
        assertThat("A.path", cookies[0].getPath(), nullValue());
        assertEquals("A.domain", "a.com", cookies[0].getDomain());
    }

    /**
     * CVE-2023-26049 / GHSA-p26g-97m4-6q7c: an attacker controlled cookie with a quoted value
     * must not smuggle the value of a following (possibly HttpOnly) cookie.
     */
    @Test
    public void testCookieSmuggling()
    {
        String[] smuggled = new String[]
        {
            // The advisory example
            "DISPLAY_LANGUAGE=\"b; JSESSIONID=1337; c=d\"",
            // Smuggled cookie last, so the quote is never terminated
            "DISPLAY_LANGUAGE=\"b; JSESSIONID=1337",
            // The ';' separator escaped by a trailing backslash in the attacker controlled value
            "DISPLAY_LANGUAGE=\"b\\; JSESSIONID=1337",
            "DISPLAY_LANGUAGE=\"b\\; JSESSIONID=1337\"",
            "DISPLAY_LANGUAGE=\"b\\; JSESSIONID=1337; c=d\"",
            // Without the space a browser would add after the ';'
            "DISPLAY_LANGUAGE=\"b;JSESSIONID=1337;c=d\"",
            // With a legitimate cookie before the attacker controlled one
            "lang=en; DISPLAY_LANGUAGE=\"b; JSESSIONID=1337; c=d\"",
        };

        for (String input : smuggled)
        {
            Cookie[] cookies = parseCookieHeaders(input);
            for (Cookie cookie : cookies)
            {
                assertThat("Cookie.name of <" + input + ">", cookie.getName(), not(is("DISPLAY_LANGUAGE")));
                assertThat("Cookie.value of <" + input + ">", cookie.getValue(), not(containsString("JSESSIONID")));
                assertThat("Cookie.value of <" + input + ">", cookie.getValue(), not(containsString("1337")));
            }
        }
    }
}
