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

        public ReferenceType ReferenceType { get; set; }

        private AssemblyDefinition _assemblyDefinition;
        private readonly ReaderParameters _readerParameters;

        private string AssemblyFilePath => InitialTaskItem.ItemSpec;

        /// <summary>
        /// Returns true if the assembly is strong name signed or delay signed.
        /// </summary>
        public bool IsSigned => _assemblyDefinition.Name.HasPublicKey;

        public string AssemblyName => _assemblyDefinition.Name.FullName;

        public IEnumerable<string> InitialUnsignedReferences => UnsignedAssemblyNameReferences.Select(x => x.FullName);

        private IEnumerable<AssemblyNameReference> UnsignedAssemblyNameReferences => _assemblyDefinition.MainModule
            .AssemblyReferences
            .Where(ass => ass.PublicKeyToken.Length == 0);

        /// <summary>
        /// Count of referenced assemblies that are not yet signed.
        /// </summary>
        public int ReferencedUnsignedAssemblies { get; set; }

        private readonly IList<string> _referencingAssemblies = new List<string>();

        /// <summary>
        /// List of assemblies referencing this assembly. 
        /// </summary>
        /// <remarks>
        /// If we have A => B then B.ReferencingAssemblies contains A.
        /// ReferencedUnsignedAssemblies for A is 1 at the start, until B gets signed.
        /// B always has ReferencedUnsignedAssemblies = 0.
        /// </remarks>
        public IReadOnlyCollection<string> ReferencingAssemblies { get; }

        /// <summary>
        /// TaskItem of signed assembly. Can be the same as the initial one, if it was already signed.
        /// </summary>
        public ITaskItem SignedTaskItem { get; private set; }

        public AssemblyInformation(ITaskItem initialTaskItem, AssemblyDefinition assemblyDefinition, ReaderParameters readerParameters)
        {
            // The AssemblyDefinition is disposed and was initialized with deferred reading. 
            // We have to be careful what we do with it.
            InitialTaskItem = initialTaskItem;
            _assemblyDefinition = assemblyDefinition;
            _readerParameters = readerParameters;
            ReferencingAssemblies = new ReadOnlyCollection<string>(_referencingAssemblies);
            ReferencedUnsignedAssemblies = InitialUnsignedReferences.Count();
            if (IsSigned)
            {
                SignedTaskItem = InitialTaskItem;
            }
        }

        public void AddReferencingAssembly(string assemblyName)
        {
            _referencingAssemblies.Add(assemblyName);
        }

        public bool HasUnsignedReferences() => ReferencedUnsignedAssemblies != 0;

        public void Sign(string baseOutputDir, PublicKeyData publicKeyData)
        {
            if (HasUnsignedReferences())
            {
                throw new InvalidOperationException("Cannot sign assembly with outstanding unsigned references.");
            }
            // Replace the assemblydefinition with an open one for the duration of the write calls.
            using (_assemblyDefinition =
                Mono.Cecil.AssemblyDefinition.ReadAssembly(InitialTaskItem.ItemSpec, _readerParameters))
            {
                var outputFile = GetOutputFile(baseOutputDir);
                File.Delete(outputFile);
                SignedTaskItem = new TaskItem(InitialTaskItem)
                {
                    ItemSpec = outputFile
                };
                SetPublicKeyTokenOnReferences(publicKeyData.PublicKeyToken);
                FixInternalsVisibleTo();
                _assemblyDefinition.Write(outputFile, GetWriterParameters(publicKeyData.StrongNameKeyPair));
            }
        }

        private void FixInternalsVisibleTo()
        {
            var internalsVisibleToAttributes = _assemblyDefinition.CustomAttributes.Where(attr =>
                attr.AttributeType.FullName == typeof(InternalsVisibleToAttribute).FullName).ToList();
            foreach (var att in internalsVisibleToAttributes)
            {
                // TODO Rewrite if referencing without public key token
                //AssemblyDefinition.CustomAttributes.Remove(att);
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
