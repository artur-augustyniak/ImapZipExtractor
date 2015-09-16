package pl.aaugustyniak.imapzipextractor.extractor;

import com.google.code.tempusfugit.concurrency.ConcurrentRule;
import com.google.code.tempusfugit.concurrency.ConcurrentTestRunner;
import com.google.code.tempusfugit.concurrency.RepeatingRule;
import com.google.code.tempusfugit.concurrency.annotations.Concurrent;
import com.google.code.tempusfugit.concurrency.annotations.Repeating;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import javax.mail.MessagingException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.runner.RunWith;

/**
 * @author aaugustyniak
 */
@RunWith(ConcurrentTestRunner.class)
public class ImapZipFilesExtractorTest {

    private static final int CYCLES = 2;
    private static final int THREADS = 5;
    private static final boolean CONNECTORS_DEBUG_MODE = true;

    private static ImapZipFilesExtractor csfe;
    private static ImapZipFilesExtractor csfeNTLMAuth;

    /**
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.mail.MessagingException
     */
    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException, MessagingException {
        String host = "myhost";
        String userName = "myuser";
        String passwd = "mypass";
        String imapFolder = "INBOX";
        String attachmentsFolder = "/tmp/mail/";

        csfe = new ImapZipFilesExtractor(host,
                userName,
                passwd,
                imapFolder,
                attachmentsFolder
        );

        csfe.cleanupWorkingDirectory();
        csfe.init(CONNECTORS_DEBUG_MODE);

        String ntlmDomain = "MY_DOMAIN";

        csfeNTLMAuth = new ImapZipFilesExtractor(host,
                userName,
                passwd,
                imapFolder,
                attachmentsFolder,
                ntlmDomain,
                ImapZipFilesExtractor.NTLM_DEFAULT_FLAGS
        );

        csfeNTLMAuth.cleanupWorkingDirectory();
        csfeNTLMAuth.init(CONNECTORS_DEBUG_MODE);
    }

    @Rule
    public ConcurrentRule rule = new ConcurrentRule();
    @Rule
    public RepeatingRule repeatedly = new RepeatingRule();

    @Test
    @Concurrent(count = THREADS)
    @Repeating(repetition = CYCLES)
    public void testJustRunPLAINauth() throws MessagingException, IOException {
        csfe.process();
        for (File f : csfe.getUnzippedAttachments()) {
            System.out.println(f.getAbsolutePath());
        }
    }

    @Test
    @Concurrent(count = THREADS)
    @Repeating(repetition = CYCLES)
    public void testJustRunNTLMauth() throws MessagingException, IOException {
        csfeNTLMAuth.process();
        for (File f : csfeNTLMAuth.getUnzippedAttachments()) {
            System.out.println(f.getAbsolutePath());
        }
    }

}
