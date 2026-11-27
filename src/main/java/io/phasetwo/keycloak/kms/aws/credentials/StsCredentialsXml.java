package io.phasetwo.keycloak.kms.aws.credentials;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.spi.KmsException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Reads the {@code <Credentials>} element of an STS response. {@code AssumeRole} and {@code
 * AssumeRoleWithWebIdentity} answer in XML only, with the same element names.
 */
final class StsCredentialsXml {

  private StsCredentialsXml() {}

  static AwsCredentials parse(String xml, String source) {
    try {
      // Parsing untrusted-shaped XML means turning off doctypes and external entities explicitly;
      // the defaults are not safe.
      DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
      f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      f.setFeature("http://xml.org/sax/features/external-general-entities", false);
      f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      f.setXIncludeAware(false);
      f.setExpandEntityReferences(false);
      Document doc =
          f.newDocumentBuilder()
              .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

      String accessKeyId = first(doc, "AccessKeyId");
      String secret = first(doc, "SecretAccessKey");
      String sessionToken = first(doc, "SessionToken");
      String expiration = first(doc, "Expiration");
      if (accessKeyId == null || secret == null) {
        // Never echo the body: on success it holds a secret, and this branch means it was not
        // shaped as expected, so there is no telling what it holds.
        throw new KmsException("STS response contained no credentials");
      }
      return new AwsCredentials(
          accessKeyId,
          secret,
          sessionToken,
          expiration == null ? null : Instant.parse(expiration),
          source);
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new KmsException("could not parse the STS response", e);
    }
  }

  private static String first(Document doc, String tag) {
    NodeList n = doc.getElementsByTagName(tag);
    return n.getLength() == 0 ? null : n.item(0).getTextContent().trim();
  }
}
