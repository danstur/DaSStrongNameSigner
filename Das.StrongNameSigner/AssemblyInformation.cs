using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Mono.Cecil;

namespace DaS.StrongNameSigner
{
    [DebuggerDisplay("{AssemblyName}")]
    internal sealed class AssemblyInformation
    {
        private ITaskItem InitialTaskItem { get; }

        private AssemblyDefinition _assemblyDefinition;

        private readonly ReaderParameters _readerParameters;

        private string AssemblyFilePath => InitialTaskItem.ItemSpec;

        /// <summary>
        /// Returns true if the assembly is strong name signed or delay signed.
        /// </summary>
        public bool IsSigned => _assemblyDefinition.Name.HasPublicKey;

        public string AssemblyName => _assemblyDefinition.Name.FullName;

        private IEnumerable<AssemblyNameReference> UnsignedAssemblyNameReferences => _assemblyDefinition.MainModule
            .AssemblyReferences
            .Where(ass => ass.PublicKeyToken.Length == 0);

        public AssemblyInformation(ITaskItem initialTaskItem, AssemblyDefinition assemblyDefinition, ReaderParameters readerParameters)
        {
            // The AssemblyDefinition is disposed and was initialized with deferred reading. 
            // We have to be careful what we do with it.
            InitialTaskItem = initialTaskItem;
            _assemblyDefinition = assemblyDefinition;
            _readerParameters = readerParameters;
        }

        public bool TrySign(string baseOutputDir, PublicKeyData publicKeyData, out ITaskItem signedTaskItem)
        {
            if (IsSigned)
            {
                signedTaskItem = InitialTaskItem;
                return false;
            }
            // Replace the assemblydefinition with an open one for the duration of the write calls.
            using (_assemblyDefinition =
                Mono.Cecil.AssemblyDefinition.ReadAssembly(InitialTaskItem.ItemSpec, _readerParameters))
            {
                var outputFile = GetOutputFile(baseOutputDir);
                File.Delete(outputFile);
                var taskItem = new TaskItem(InitialTaskItem)
                {
                    ItemSpec = outputFile
                };
                SetPublicKeyTokenOnReferences(publicKeyData.PublicKeyToken);
                FixInternalsVisibleTo(publicKeyData);
                _assemblyDefinition.Write(outputFile, GetWriterParameters(publicKeyData.StrongNameKeyPair));
                signedTaskItem = taskItem;
                return true;
            }
        }

        private void FixInternalsVisibleTo(PublicKeyData publicKeyData)
        {
            var internalsVisibleToAttributes = _assemblyDefinition.CustomAttributes.Where(attr =>
                attr.AttributeType.FullName == typeof(InternalsVisibleToAttribute).FullName).ToList();
            foreach (var att in internalsVisibleToAttributes)
            {
                if (att.ConstructorArguments.Count != 1)
                {
                    throw new InvalidOperationException("InternalsVisibleToAttribute does not have a single constructor argument.");
                }
                var assemblyNameArgument = att.ConstructorArguments.First();
                var assemblyName = (string) assemblyNameArgument.Value;
                if (!assemblyName.Contains("PublicKey"))
                {
                    assemblyName = $"{assemblyName},PublicKey={publicKeyData.PublicKeyTokenAsString}";
                    att.ConstructorArguments.Clear();
                    att.ConstructorArguments.Add(new CustomAttributeArgument(assemblyNameArgument.Type, assemblyName));
                }
            }
        }

        private string GetOutputFile(string baseOutputDir)
        {
            var subDirectory = InitialTaskItem.GetMetadata("DestinationSubDirectory");
            var outputDirectory = Path.Combine(baseOutputDir, subDirectory);
            if (!Directory.Exists(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }
            var outputFile = Path.Combine(outputDirectory, Path.GetFileName(AssemblyFilePath));
            return outputFile;
        }

        private void SetPublicKeyTokenOnReferences(byte[] publicKeyToken)
        {
            foreach (var reference in UnsignedAssemblyNameReferences)
            {
                // We know that all unsigned references were signed with the given key
                reference.PublicKeyToken = publicKeyToken;
            }
        }

        private WriterParameters GetWriterParameters(StrongNameKeyPair strongNameKeyPair)
        {
            var pdbPath = AssemblyFilePath.Substring(0, AssemblyFilePath.LastIndexOf('.')) + ".pdb";
            return new WriterParameters()
            {
                StrongNameKeyPair = strongNameKeyPair,
                WriteSymbols = File.Exists(pdbPath)
            };
        }
    }
}
