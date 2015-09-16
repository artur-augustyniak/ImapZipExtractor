package pl.aaugustyniak.imapzipextractor.extractor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.mail.*;
import javax.mail.search.FlagTerm;

/**
 * Created by aaugustyniak on 14.09.15.
 */
public class ImapZipFilesExtractor {

    private final static String USE_INIT_ERR_MSG = "Komponent nie został "
            + "poprawnie zainicjalizowany "
            + "lub nie udało się połączyc z serwerem "
            + "pocztowym. Czy użyłeś metody init() tylko jeden raz?";

    private final static String ZIP_FILE_EXT = ".zip";

    /**
     * @see http://curl.haxx.se/rfc/ntlm.html#theNtlmFlags
     *
     * As an default:
     * 
     * Negotiate Unicode        (0x00000001) 
     * Request Target           (0x00000004) 
     * Negotiate NTLM           (0x00000200)
     * Negotiate Always Sign    (0x00008000)
     *
     * Combining the above gives "0x00008205". 
     * This would be physically laid out as "0x05820000" 
     * (since it is represented in little-endian byte order).
     */
    public final static int NTLM_DEFAULT_FLAGS
            = 0x00000001
            | 0x00000004
            | 0x00000200
            | 0x00008000;

    private final static int FLAG_DISABLE_NTLM = 0x0;
    private final static String NO_NTLM_DOMAIN = "0x0";

    private int customNtlmFlags = 0;

    private final String host;
    private final String userName;
    private final String passwd;
    private final String imapFolder;
    private String ntlmDomain;
    private final String attachmentsFolder;
    private final Properties props;
    private volatile Session session;
    private final List<File> unzippedAttachments;
    private MessageDigest md;
    private Store store;
    private volatile Folder inbox;

    public ImapZipFilesExtractor(String host,
            String userName,
            String passwd,
            String imapFolder,
            String attachmentsFolder
    ) throws NoSuchAlgorithmException, MessagingException {
        this(host,
                userName,
                passwd,
                imapFolder,
                attachmentsFolder,
                NO_NTLM_DOMAIN,
                FLAG_DISABLE_NTLM);
    }

    public ImapZipFilesExtractor(String host,
            String userName,
            String passwd,
            String imapFolder,
            String attachmentsFolder,
            String ntlmDomain,
            int customNtlmFlags
    ) throws NoSuchAlgorithmException, NoSuchProviderException, MessagingException {

        this.host = host;
        this.userName = userName;
        this.passwd = passwd;
        this.imapFolder = imapFolder;
        this.attachmentsFolder = attachmentsFolder;
        this.customNtlmFlags = customNtlmFlags;
        this.ntlmDomain = ntlmDomain;

        props = new Properties();
        props.setProperty("mail.store.protocol", "imaps");

        if (FLAG_DISABLE_NTLM < this.customNtlmFlags) {
            props.setProperty("mail.imaps.auth.ntlm.domain", this.ntlmDomain);
            String texturalFlagRepr;
            if (0 < this.customNtlmFlags) {
                texturalFlagRepr = String.valueOf(customNtlmFlags);
            } else {
                texturalFlagRepr = String.valueOf(NTLM_DEFAULT_FLAGS);
            }
            props.setProperty("mail.imaps.auth.ntlm.flags", texturalFlagRepr);
            props.setProperty("mail.imaps.auth.plain.disable", "true");
        }
        session = Session.getInstance(props, null);
        unzippedAttachments = new ArrayList<>();
    }

    public synchronized void init() throws NoSuchAlgorithmException, MessagingException {
        md = MessageDigest.getInstance("SHA1");
        store = session.getStore();
        store.connect(host, userName, passwd);
        inbox = store.getFolder(imapFolder);
        inbox.open(Folder.READ_WRITE);
    }

    public synchronized void init(boolean debug) throws NoSuchAlgorithmException, MessagingException {
        session.setDebug(debug);
        init();
    }

    public synchronized void process() throws MessagingException, IOException {
        if (null == inbox) {
            throw new RuntimeException(USE_INIT_ERR_MSG);
        }
        /**
         * Tylko nieprzeczytane wiadomości tu można by też dodać filtrowanie po
         * temacie
         */
        Message messages[] = inbox.search(new FlagTerm(new Flags(Flags.Flag.SEEN), false));
        for (Message msg : messages) {
            processMessage(msg);
        }

    }

    private void processMessage(Message msg) throws MessagingException, IOException {
        md.update(msg.getReceivedDate().toString().getBytes());
        byte[] output = md.digest();
        String msgSha = bytesToHex(output);
        logMsgProcessing(msg, msgSha);
        Multipart msgContent = (Multipart) msg.getContent();
        processAttachemnts(msgSha, msgContent);
        msg.setFlag(Flags.Flag.SEEN, true);
    }

    private void processAttachemnts(String msgSha, Multipart msgContent) throws MessagingException, IOException {
        for (int i = 0; i < msgContent.getCount(); i++) {
            BodyPart bodyPart = msgContent.getBodyPart(i);
            if (!Part.ATTACHMENT.equalsIgnoreCase(bodyPart.getDisposition())
                    && !"".equals(bodyPart.getFileName())) {
                continue;
            }
            extractZipAttachments(msgSha, bodyPart);
        }
    }

    private void logMsgProcessing(Message msg, String msgSha) throws MessagingException {
        Address[] in = msg.getFrom();
        for (Address address : in) {
            String logMsg = String.format("FROM %s", address.toString());
            Logger.getLogger(ImapZipFilesExtractor.class.getName()).log(Level.INFO, logMsg);
        }

        String logMsg = String.format("SENT DATE: %s\n"
                + "SUBJECT: %s\n"
                + "SHA-1: %s", msg.getSentDate(), msg.getSubject(), msgSha);
        Logger.getLogger(ImapZipFilesExtractor.class.getName()).log(Level.INFO, logMsg);
    }

    private void extractZipAttachments(String msgSha, BodyPart bodyPart) throws IOException, MessagingException {
        InputStream is = bodyPart.getInputStream();
        if (bodyPart.getFileName().endsWith(ZIP_FILE_EXT)) {

            File f = new File(attachmentsFolder + msgSha + "_" + bodyPart.getFileName());
            try (FileOutputStream fos = new FileOutputStream(f)) {
                byte[] buf = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buf)) != -1) {
                    fos.write(buf, 0, bytesRead);
                }
            }

            try (ZipFile zipFile = new ZipFile(f)) {
                Enumeration<?> enu = zipFile.entries();
                while (enu.hasMoreElements()) {
                    ZipEntry zipEntry = (ZipEntry) enu.nextElement();

                    String name = zipEntry.getName();
                    long size = zipEntry.getSize();
                    long compressedSize = zipEntry.getCompressedSize();
                    String logMsg1 = String.format("name: %-20s | size: %6d | compressed size: %6d\n", name, size, compressedSize);
                    Logger.getLogger(ImapZipFilesExtractor.class.getName()).log(Level.INFO, logMsg1);

                    File file = new File(attachmentsFolder + msgSha + "_" + name);
                    if (name.endsWith("/")) {
                        file.mkdirs();
                        continue;
                    }

                    File parent = file.getParentFile();
                    if (parent != null) {
                        parent.mkdirs();
                    }

                    FileOutputStream fos;
                    try (InputStream isa = zipFile.getInputStream(zipEntry)) {
                        fos = new FileOutputStream(file);
                        byte[] bytes = new byte[1024];
                        int length;
                        while ((length = isa.read(bytes)) >= 0) {
                            fos.write(bytes, 0, length);
                        }
                    }
                    fos.close();
                    unzippedAttachments.add(file);

                }
                f.delete();

            }
        } else {
            String logMsg2 = String.format("IGNORING NO %s FILES FOUND", ZIP_FILE_EXT);
            Logger.getLogger(ImapZipFilesExtractor.class.getName()).log(Level.INFO, logMsg2);
        }
    }

    public List<File> getUnzippedAttachments() {
        return unzippedAttachments;
    }

    public synchronized void cleanupWorkingDirectory() {
        File dir = new File(attachmentsFolder);
        for (File file : dir.listFiles()) {
            file.delete();
        }
    }

    private String bytesToHex(byte[] b) {
        char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder();
        for (int j = 0; j < b.length; j++) {
            buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
            buf.append(hexDigit[b[j] & 0x0f]);
        }
        return buf.toString();
    }

}
