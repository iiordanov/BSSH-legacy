/*
 * File Chooser Class for VX ConnectBot
 * Copyright 2012 Martin Matuska
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.iiordanov.bssh.util;

import java.io.File;
import java.net.URI;

import org.openintents.intents.FileManagerIntents;

import com.iiordanov.bssh.R;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;

import com.lamerman.FileDialog;
import com.lamerman.SelectionMode;

public class FileChooser {
	public final static String TAG = "ConnectBot.FileChooser";

	public static final int REQUEST_CODE_SELECT_FILE = 1;

	// Constants for AndExplorer's file picking intent
	private static final String ANDEXPLORER_TITLE = "explorer_title";
	private static final String MIME_TYPE_ANDEXPLORER_FILE = "vnd.android.cursor.dir/lysesoft.andexplorer.file";

	public static void selectFile(Activity source, FileChooserCallback callback, int requestcode) {
		selectFile(source, callback, requestcode, null);
	}

	public static void selectFile(Activity source, FileChooserCallback callback, int requestcode, String title) {
		final File sdcard = Environment.getExternalStorageDirectory();
		if (title == null)
			title = source.getString(R.string.file_chooser_select_file);
		int mode = SelectionMode.MODE_OPEN;
		SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(source);
		Intent intent = null;
		String filedialog;
		String appString = null;

		if (prefs == null)
			return;
		filedialog = prefs.getString(PreferenceConstants.FILE_DIALOG, "built-in");

		if (filedialog.equals("OI")) {
			appString = "OpenIntents File Manager";
			intent = new Intent(FileManagerIntents.ACTION_PICK_FILE);
			intent.setData(Uri.fromFile(sdcard));
			intent.putExtra(FileManagerIntents.EXTRA_TITLE, title);
			intent.putExtra(FileManagerIntents.EXTRA_BUTTON_TEXT, source.getString(android.R.string.ok));
		} else if (filedialog.equals("AE")) {
			appString = "AndExplorer";
			intent = new Intent(Intent.ACTION_PICK);
			intent.setDataAndType(Uri.fromFile(sdcard), MIME_TYPE_ANDEXPLORER_FILE);
			intent.putExtra(ANDEXPLORER_TITLE, title);
		}
		if (intent != null && appString != null) {
			try {
				source.startActivityForResult(intent, requestcode);
				return;
			} catch (ActivityNotFoundException e1) {
				Toast.makeText(source,
						source.getString(R.string.error_starting_app, appString),
						Toast.LENGTH_LONG).show();
			}
		}
		intent = new Intent(source.getBaseContext(), FileDialog.class);
		intent.putExtra(FileDialog.START_PATH, sdcard.toString());
		intent.putExtra(FileDialog.TITLE, title);
		intent.putExtra(FileDialog.SELECTION_MODE, mode);
		source.startActivityForResult(intent, requestcode);
	}

	public static File getSelectedFile(Intent intent) {
		File file = null;

		if (intent == null)
			return null;

		Uri uri = intent.getData();
		try {
			if (uri != null) {
				file = new File(URI.create(uri.toString()));
			} else {
				String filename = intent.getDataString();
				if (filename != null)
					file = new File(URI.create(filename));
			}
		} catch (IllegalArgumentException e) {
			Log.e(TAG, "Couldn't read selected file", e);
			return null;
		}

		return file;
	}
}