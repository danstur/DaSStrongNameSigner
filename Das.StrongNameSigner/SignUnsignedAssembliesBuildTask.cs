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

        private IImmutableList<string> _probingPaths;

        private ReaderParameters _readerParameters;

        private IImmutableDictionary<string, AssemblyInformation> _assemblyNameToInformationMap;

        /// <summary> 
        /// Stack of all assemblies that are unsigned but do not reference any unsigned assemblies any longer.
        /// </summary>
        private Stack<AssemblyInformation> _assembliesWithoutUnsignedReferences;

        private string _signedAssemblyDirectory;

        private PublicKeyData _publicKeyData;

        public override bool Execute()
        {
            try
            {
                Log.LogMessage(MessageImportance.Normal, "---- .NET Assembly Strong-Name Signer ----");
                SignAllAssemblies();
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

            _assemblyNameToInformationMap = References.Select(reference =>
                    (referenceType: ReferenceType.Normal, assemblyInfo: GetAssemblyInfo(reference)))
                .Union(
                    ReferenceCopyLocalPaths
                        .Where(IsValidDotNetReference)
                        .Select(reference =>
                        (referenceType: ReferenceType.CopyLocal, assemblyInfo: GetAssemblyInfo(reference)))
                )
                .GroupBy(x => x.assemblyInfo.AssemblyName)
                .ToImmutableDictionary(x => x.Key, x =>
                {
                    // Set the ReferenceType correctly if the assembly should be referenced
                    // in both References and ReferenceCopyLocalPaths.
                    var firstElement = x.First();
                    var referenceType = x.AsEnumerable().Select(a => a.referenceType).Aggregate(ReferenceType.None,
                        (currentType, newType) => currentType | newType);
                    firstElement.assemblyInfo.ReferenceType = referenceType;
                    return firstElement.assemblyInfo;
                });

            ComputeReferencingAssemblies();

            _assembliesWithoutUnsignedReferences = new Stack<AssemblyInformation>(_assemblyNameToInformationMap
                .Values
                .Where(ass => !ass.IsSigned)
                .Where(ass => !ass.HasUnsignedReferences()));

            while (_assembliesWithoutUnsignedReferences.Any())
            {
                var assembly = _assembliesWithoutUnsignedReferences.Pop();
                SignAssembly(assembly);
            }

            SignedReferences = _assemblyNameToInformationMap.Values
                .Where(x => x.ReferenceType.HasFlag(ReferenceType.Normal)).Select(x => x.SignedTaskItem).ToArray();
            SignedReferenceCopyLocalPaths = _assemblyNameToInformationMap.Values
                .Where(x => x.ReferenceType.HasFlag(ReferenceType.CopyLocal)).Select(x => x.SignedTaskItem)
                .Concat(ReferenceCopyLocalPaths.Where(reference => !IsValidDotNetReference(reference)))
                
                .ToArray();
        }

        private bool IsValidDotNetReference(ITaskItem item)
        {
            return item.ItemSpec.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                item.ItemSpec.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        }

        private PublicKeyData GetPublicKeyData()
        {
            var assemblyassemblyLocationDir = new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath;
            var assemblyDir = Path.GetDirectoryName(assemblyassemblyLocationDir);
            var keyFilePath = Path.Combine(assemblyDir, "signingkey.snk");
            var publicKey = File.ReadAllBytes(keyFilePath);
            return new PublicKeyData(publicKey);
        }

        private void SignAssembly(AssemblyInformation assembly)
        {
            Log.LogMessage(MessageImportance.Normal, $"Sign assembly {assembly.AssemblyName}");
            assembly.Sign(_signedAssemblyDirectory, _publicKeyData);
            foreach (var referencingAssemblyName in assembly.ReferencingAssemblies)
            {
                var referencingAssembly = _assemblyNameToInformationMap[referencingAssemblyName];
                referencingAssembly.ReferencedUnsignedAssemblies--;
                if (!referencingAssembly.HasUnsignedReferences())
                {
                    _assembliesWithoutUnsignedReferences.Push(referencingAssembly);
                }
            }
        }

        private void ComputeReferencingAssemblies()
        {
            foreach (var assembly in _assemblyNameToInformationMap.Values.Where(x => !x.IsSigned))
            {
                foreach (var reference in assembly.InitialUnsignedReferences)
                {
                    var referencedAssembly = _assemblyNameToInformationMap[reference];
                    referencedAssembly.AddReferencingAssembly(assembly.AssemblyName);
                }
            }
        }

        private AssemblyInformation GetAssemblyInfo(ITaskItem referenceItem)
        {
            var assemblyPath = referenceItem.ItemSpec;
            var assemblyDefinition = AssemblyDefinition.ReadAssembly(assemblyPath, _readerParameters);
            return new AssemblyInformation(referenceItem, assemblyDefinition);
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
