using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Build.Framework;
using Mono.Cecil;

namespace DaS.StrongNameSigner
{
    public sealed class SignUnsignedAssembliesBuildTask : Microsoft.Build.Utilities.Task
    {
        [Required]
        public ITaskItem[] References { get; set; }

        [Required]
        public ITaskItem[] ReferenceCopyLocalPaths { get; set; }

        [Required]
        public ITaskItem OutputPath { get; set; }

        [Output]
        public ITaskItem[] SignedReferences { get; set; }

        [Output]
        public ITaskItem[] SignedReferenceCopyLocalPaths { get; set; }

        [Output]
        public ITaskItem[] TemporaryFilesToClean { get; set; }

        private readonly IList<ITaskItem> _temporaryFilesToClean = new List<ITaskItem>();

        private IImmutableList<string> _probingPaths;

        private ReaderParameters _readerParameters;

        private string _signedAssemblyDirectory;

        private PublicKeyData _publicKeyData;

        public override bool Execute()
        {
            try
            {
                Log.LogMessage(MessageImportance.Normal, "---- .NET Assembly Strong-Name Signer ----");
                SignAllAssemblies();
                TemporaryFilesToClean = _temporaryFilesToClean.ToArray();
                return true;
            }
            catch (Exception e)
            {
                Log.LogErrorFromException(e, true, true, null);
                return false;
            }
        }

        private void SignAllAssemblies()
        {
            _signedAssemblyDirectory = Path.Combine(OutputPath.ItemSpec, "DaS.StrongNameSigner");
            if (!Directory.Exists(_signedAssemblyDirectory))
            {
                Directory.CreateDirectory(_signedAssemblyDirectory);
            }
            _publicKeyData = GetPublicKeyData();
            _probingPaths = References.Union(ReferenceCopyLocalPaths)
                .Select(reference => Path.GetDirectoryName(reference.ItemSpec))
                .ToImmutableList();
            _readerParameters = GetReaderParameters();

            // Do the local paths first, to make sure we use the actual reference file.
            SignedReferenceCopyLocalPaths = ReferenceCopyLocalPaths.Select(SignAssembly).ToArray();
            SignedReferences = References.Select(SignAssembly).ToArray();
        }

        private ITaskItem SignAssembly(ITaskItem reference)
        {
            if (!IsValidDotNetReference(reference))
            {
                return reference;
            }
            var assemblyInfo = GetAssemblyInfo(reference);
            var hadToSign = assemblyInfo.TrySign(_signedAssemblyDirectory, _publicKeyData, out var signedTaskItem);
            if (hadToSign)
            {
                // Files added to this list are added to the FileWrites msbuild property.
                // Everything included in this property is added to the FileListAbsolute.txt
                // file which is used to decide what files to delete when MSBuild clean is called.
                _temporaryFilesToClean.Add(signedTaskItem);
            }
            return signedTaskItem;
        }

        private bool IsValidDotNetReference(ITaskItem item)
        {
            // Ignore pdbs. Also if the file does not exist, it probably is part of the build
            // and being created at which point we are not responsible for signing it anyhow.
            // TODO This could be problematic with native assemblies that are referenced. 
            var path = item.ItemSpec;
            var isAssembly = path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
            return isAssembly && File.Exists(path);
        }

        private PublicKeyData GetPublicKeyData()
        {
            var assemblyassemblyLocationDir = new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath;
            var assemblyDir = Path.GetDirectoryName(assemblyassemblyLocationDir);
            var keyFilePath = Path.Combine(assemblyDir, "signingkey.snk");
            var publicKey = File.ReadAllBytes(keyFilePath);
            return new PublicKeyData(publicKey);
        }

        private AssemblyInformation GetAssemblyInfo(ITaskItem referenceItem)
        {
            var assemblyPath = referenceItem.ItemSpec;
            using (var assemblyDefinition = AssemblyDefinition.ReadAssembly(assemblyPath, _readerParameters))
            {
                return new AssemblyInformation(referenceItem, assemblyDefinition, _readerParameters);
            }
        }

        private ReaderParameters GetReaderParameters()
        {
            var resolver = new DefaultAssemblyResolver();
            foreach (var probingPath in _probingPaths)
            {
                resolver.AddSearchDirectory(probingPath);
            }
            return new ReaderParameters()
            {
                AssemblyResolver = resolver
            };
        }
    }
}
