package de.chrfritz.oidc.auth.oauth.pkce_flow;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SystemUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * Small utility class to open a website within the browser.
 */
@Slf4j
@UtilityClass
class Browser {
    /**
     * Open the given URI within the browser.
     *
     * @param uri The URI to open.
     */
    static Process openAsApp(URI uri) {
        List<String> args;

        if (SystemUtils.IS_OS_MAC) {
            Path chrome = Paths.get("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
            if (Files.exists(chrome)) {
                args = Arrays.asList(chrome.toString(), "--window-size=900,900", "--app=" + uri.toString());
            }
            else {
                args = Arrays.asList("open", uri.toString());
            }
        }
        else if (SystemUtils.IS_OS_WINDOWS) {
            args = Arrays.asList(/*"start",*/ "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "--window-size=900,900",
                "--app=" + uri.toString());
        }
        else {
            throw new IllegalStateException("Unknown operating system");
        }

        try {
            LOGGER.debug("Open {} in browser with command '{}'", uri, String.join(" ", args));
            return Runtime.getRuntime().exec(args.toArray(new String[0]));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
