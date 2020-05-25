package com.dreamsecurity.ocsputility;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Contains functions related to general manipulation of system file/folder
 * 
 * @author dream
 *
 */
public class FileUtils {
	private static final Logger logger = LogManager.getLogger(FileUtils.class);

	public static X509Certificate readX509Certificate(String filePath) {
		CertificateFactory cf = null;

		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			logger.error("Error in creating CertificateFactory instance: "
					+ e.getMessage());
			e.printStackTrace();
			return null;
		}

		try {
			return (X509Certificate) cf.generateCertificate(
					new ByteArrayInputStream(readFromFile(filePath)));
		} catch (CertificateException e) {
			logger.error("Error in generating certificate instance: "
					+ e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

	public static void saveFile(String name, byte[] data) {
		OutputStream os = null;
		try {
			os = new FileOutputStream(name);

			os.write(data);
			os.flush();
			os.close();
		} catch (IOException e) {
			logger.error("Error in saving file", e.getMessage());
			e.printStackTrace();
			return;
		}
	}

	/**
	 * Recursively deletes a file. If file is a directory, then it will delete
	 * all files and subdirectories contained.
	 * 
	 * @param file
	 *            the file to delete
	 */
	public static void delete(File file) {
		if (file.isDirectory()) {
			for (File subFile : file.listFiles()) {
				delete(subFile);
			}
		}
		if (!file.delete()) {
			logger.error(
					"Could not delete directory " + file.getAbsolutePath());
		}
	}

	public static int deleteDir(final File source) {
		int ret = 0;

		if (source.exists()) {
			File[] files = source.listFiles();
			for (File file : files) {
				if (file.isDirectory()) {
					deleteDir(file);
				} else if (!file.delete()) {
					logger.error(
							"Unable to delete file: " + file.getAbsolutePath());
					ret = 1;
				}
			}

			source.delete();
		} else {
			logger.error("Unable to delete directory: Source path not found: "
					+ source.getAbsolutePath());
			return 1;
		}

		return ret;
	}

	public static void copyDir(final File source, final File dest,
			final boolean overwrite) throws IOException, FileNotFoundException {
		copyDir(source, dest, overwrite, false);
	}

	public static void copyDir(final File source, final File dest,
			final boolean overwrite, final boolean mergeConfigProperties)
			throws IOException, FileNotFoundException {
		if (source.exists()) {
			File[] files = source.listFiles();

			if (!dest.exists())
				dest.mkdirs();

			for (File file : files) {
				if (file.isDirectory())
					copyDir(file,
							new File(dest.getAbsolutePath()
									+ System.getProperty("file.separator")
									+ file.getName()),
							overwrite, mergeConfigProperties);
				else {
					if (file.getName().equals("config.properties")
							&& mergeConfigProperties) {
						mergeConfigProperties(file,
								new File(dest.getAbsolutePath()
										+ System.getProperty("file.separator")
										+ file.getName()));
					} else
						copyFile(file,
								new File(dest.getAbsolutePath()
										+ System.getProperty("file.separator")
										+ file.getName()),
								overwrite);
				}
			}
		} else
			throw new FileNotFoundException(
					"Unable to copy directory: Source path not found: "
							+ source.getAbsolutePath());
	}

	public static void copyFile(final File source, final File dest,
			final boolean overwrite) throws IOException, FileNotFoundException {
		if (dest.exists()) {
			if (overwrite)
				dest.delete();
			else
				return;
		}

		if (!dest.getParentFile().exists())
			dest.getParentFile().mkdirs();

		BufferedInputStream in = new BufferedInputStream(
				new FileInputStream(source));

		BufferedOutputStream out = new BufferedOutputStream(
				new FileOutputStream(dest, true));

		int bytes = 0;
		while ((bytes = in.read()) != -1) {
			out.write(bytes);
		}
		in.close();
		out.close();
	}

	public static String getFileContentAsString(String path) throws Exception {
		BufferedReader br = new BufferedReader(
				new InputStreamReader(new FileInputStream(path), "UTF-8"));
		String data = new String();
		try {
			String line;
			while ((line = br.readLine()) != null) {
				data = data.concat(line);
			}
		} finally {
			br.close();
		}
		return data;
	}

	public static void updatePropertiesFile(final File propertiesFile,
			final String attribute, final String value) throws IOException {
		// create file if does not exist
		if (!propertiesFile.exists()) {
			propertiesFile.getParentFile().mkdirs();
			propertiesFile.createNewFile();
		}

		String escapedValue = value.replace("\n", "\\n");

		// update if attribute exists
		boolean updated = false;
		StringBuffer buffer = new StringBuffer();
		BufferedReader in = new BufferedReader(new FileReader(propertiesFile));
		String line = null;
		while ((line = in.readLine()) != null) {
			if (line.startsWith(attribute)) {
				buffer.append(attribute + "=" + escapedValue); // append line
																// with new
																// attribute
																// value
				updated = true;
			} else
				buffer.append(line); // append old line

			buffer.append(System.getProperty("line.separator"));
		}
		in.close();

		// append attribute and value if not found in file
		if (!updated)
			buffer.append(attribute + "=" + escapedValue);

		// write output
		PrintWriter out = new PrintWriter(new FileWriter(propertiesFile));
		out.print(buffer);
		out.close();
	}

	private static void mergeConfigProperties(final File source,
			final File dest) throws IOException, FileNotFoundException {
		// read all properties from source
		Properties configProperties = new Properties();
		configProperties.load(new FileReader(source));

		// update attributes and values in destination file
		for (Enumeration<?> attributes = configProperties
				.propertyNames(); attributes.hasMoreElements();) {
			String attribute = (String) attributes.nextElement();
			String value = configProperties.getProperty(attribute);

			updatePropertiesFile(dest, attribute, value);
		}
	}

	/**
	 * Reads data from a file into a byte array
	 * 
	 * @param filename
	 *            The full file name including the path
	 * @return
	 * @throws IOException
	 */
	public static byte[] readFromFile(String filename) {
		FileInputStream stream = null;
		ByteArrayOutputStream out = null;
		try {
			byte buf[] = new byte[1024 * 32];
			stream = new FileInputStream(filename);
			BufferedInputStream in = new BufferedInputStream(stream);
			out = new ByteArrayOutputStream();

			int ret = 0;
			while ((ret = in.read(buf)) != -1) {
				out.write(buf, 0, ret);
			}

			return out.toByteArray();
		} catch (IOException e) {
			logger.error("Failed to read the file: " + e.getMessage());
			e.printStackTrace();
			return null;
		} finally {
			if (stream != null)
				try {
					stream.close();
					if (out != null) {
						out.close();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

	/**
	 * Reads data from a file into a {@link String}
	 * 
	 * @param filename
	 *            The full file name including the path
	 * @return
	 * @throws IOException
	 */
	public static String readFromFileAsString(String filename)
			throws IOException {
		return new String(readFromFile(filename));
	}

	public static boolean isFileAccessible(final String absFilePath) {
		return absFilePath != null && isFileAccessible(new File(absFilePath));
	}

	public static boolean isFileAccessible(final File file) {
		return file != null && file.exists() && file.isFile() && file.canRead();
	}

	public static boolean isDirectoryAccessible(final String absFilePath) {
		return absFilePath != null
				&& isDirectoryAccessible(new File(absFilePath));
	}

	public static boolean isDirectoryAccessible(final File file) {
		return file != null && file.exists() && file.isDirectory()
				&& file.canRead();
	}

	public static void copyFileTo(final File source, final File destination)
			throws IOException {
		Files.copy(source.toPath(), destination.toPath(),
				StandardCopyOption.COPY_ATTRIBUTES);
	}

}
