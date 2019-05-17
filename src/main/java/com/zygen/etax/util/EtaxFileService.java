package com.zygen.etax.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EtaxFileService {

	private static final Logger log = LoggerFactory.getLogger(EtaxFileService.class);

	public static void deleteTempFile(String tempPath) throws IOException {
		File file = new File(tempPath);
		if (file.exists()) {
			if (file.delete()) {
				log.info(tempPath + " Delete Completed");
			}
		} else {
			throw new IOException();
		}
	}

	public static void createTempFile(String path, InputStream inputStream) throws IOException {
		log.info("Create temp file path : " + path);
		byte[] buffer = new byte[inputStream.available()];
		inputStream.read(buffer);
		OutputStream outputStream = new FileOutputStream(path);
		outputStream.write(buffer);
		outputStream.close();
		inputStream.close();

	}
}
