//! The flag values of the table columns (ECMA-335 II.23.1).

/// The `AssemblyHashAlgorithm` values of `Assembly::hash_alg_id`
/// (II.23.1.1).
pub mod assembly_hash_algorithm {
    /// No hash.
    pub const NONE: u32 = 0x0000;
    /// MD5 (reserved).
    pub const MD5: u32 = 0x8003;
    /// SHA-1.
    pub const SHA1: u32 = 0x8004;
    /// SHA-256 (an extension of the .NET runtime).
    pub const SHA256: u32 = 0x800C;
    /// SHA-384 (an extension of the .NET runtime).
    pub const SHA384: u32 = 0x800D;
    /// SHA-512 (an extension of the .NET runtime).
    pub const SHA512: u32 = 0x800E;
}

/// The `AssemblyFlags` (II.23.1.2).
pub mod assembly_flags {
    /// The assembly reference holds the full public key, not its token.
    pub const PUBLIC_KEY: u32 = 0x0001;
    /// The runtime can bind the reference to another version.
    pub const RETARGETABLE: u32 = 0x0100;
    /// The mask of the content type (an extension of the .NET runtime).
    pub const CONTENT_TYPE_MASK: u32 = 0x0E00;
    /// The content type of a Windows Runtime assembly.
    pub const WINDOWS_RUNTIME: u32 = 0x0200;
    /// Reserved: the JIT does not optimize.
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: u32 = 0x4000;
    /// Reserved: the JIT tracks the code.
    pub const ENABLE_JIT_COMPILE_TRACKING: u32 = 0x8000;
}

/// The `EventAttributes` (II.23.1.4).
pub mod event_attributes {
    /// The name is special.
    pub const SPECIAL_NAME: u16 = 0x0200;
    /// The runtime checks the name encoding.
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
}

/// The `FieldAttributes` (II.23.1.5).
pub mod field_attributes {
    /// The mask of the accessibility.
    pub const FIELD_ACCESS_MASK: u16 = 0x0007;
    /// Not referenceable.
    pub const COMPILER_CONTROLLED: u16 = 0x0000;
    /// Accessible only by the parent type.
    pub const PRIVATE: u16 = 0x0001;
    /// Accessible by subtypes in this assembly only.
    pub const FAM_AND_ASSEM: u16 = 0x0002;
    /// Accessible in this assembly.
    pub const ASSEMBLY: u16 = 0x0003;
    /// Accessible by the type and its subtypes.
    pub const FAMILY: u16 = 0x0004;
    /// Accessible by subtypes and in this assembly.
    pub const FAM_OR_ASSEM: u16 = 0x0005;
    /// Accessible by all.
    pub const PUBLIC: u16 = 0x0006;
    /// A static field.
    pub const STATIC: u16 = 0x0010;
    /// The field is set only in the constructor.
    pub const INIT_ONLY: u16 = 0x0020;
    /// A compile-time constant.
    pub const LITERAL: u16 = 0x0040;
    /// Reserved: not serialized when the type is remoted.
    pub const NOT_SERIALIZED: u16 = 0x0080;
    /// The name is special.
    pub const SPECIAL_NAME: u16 = 0x0200;
    /// A platform invoke field.
    pub const PINVOKE_IMPL: u16 = 0x2000;
    /// The runtime checks the name encoding.
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
    /// The field has a marshalling descriptor.
    pub const HAS_FIELD_MARSHAL: u16 = 0x1000;
    /// The field has a constant.
    pub const HAS_DEFAULT: u16 = 0x8000;
    /// The field has initial data.
    pub const HAS_FIELD_RVA: u16 = 0x0100;
}

/// The `FileAttributes` (II.23.1.6).
pub mod file_attributes {
    /// The file holds metadata.
    pub const CONTAINS_METADATA: u32 = 0x0000;
    /// The file holds no metadata.
    pub const CONTAINS_NO_METADATA: u32 = 0x0001;
}

/// The `GenericParamAttributes` (II.23.1.7).
pub mod generic_param_attributes {
    /// The mask of the variance.
    pub const VARIANCE_MASK: u16 = 0x0003;
    /// Invariant.
    pub const NONE: u16 = 0x0000;
    /// Covariant.
    pub const COVARIANT: u16 = 0x0001;
    /// Contravariant.
    pub const CONTRAVARIANT: u16 = 0x0002;
    /// The mask of the special constraints.
    pub const SPECIAL_CONSTRAINT_MASK: u16 = 0x001C;
    /// The `class` constraint.
    pub const REFERENCE_TYPE_CONSTRAINT: u16 = 0x0004;
    /// The `valuetype` constraint.
    pub const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT: u16 = 0x0008;
    /// The `.ctor` constraint.
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: u16 = 0x0010;
    /// The `allows ref struct` anti-constraint (an extension of the .NET
    /// runtime).
    pub const ALLOW_BY_REF_LIKE: u16 = 0x0020;
}

/// The `PInvokeAttributes` of `ImplMap::mapping_flags` (II.23.1.8).
pub mod pinvoke_attributes {
    /// Use the member name as given.
    pub const NO_MANGLE: u16 = 0x0001;
    /// The mask of the character set.
    pub const CHAR_SET_MASK: u16 = 0x0006;
    /// No character set.
    pub const CHAR_SET_NOT_SPEC: u16 = 0x0000;
    /// ANSI strings.
    pub const CHAR_SET_ANSI: u16 = 0x0002;
    /// Unicode strings.
    pub const CHAR_SET_UNICODE: u16 = 0x0004;
    /// The platform chooses.
    pub const CHAR_SET_AUTO: u16 = 0x0006;
    /// The mask of the best-fit mapping.
    pub const BEST_FIT_MASK: u16 = 0x0030;
    /// Best-fit mapping on.
    pub const BEST_FIT_ENABLED: u16 = 0x0010;
    /// Best-fit mapping off.
    pub const BEST_FIT_DISABLED: u16 = 0x0020;
    /// The callee sets the last error.
    pub const SUPPORTS_LAST_ERROR: u16 = 0x0040;
    /// The mask of the calling convention.
    pub const CALL_CONV_MASK: u16 = 0x0700;
    /// The platform convention.
    pub const CALL_CONV_WINAPI: u16 = 0x0100;
    /// `cdecl`.
    pub const CALL_CONV_CDECL: u16 = 0x0200;
    /// `stdcall`.
    pub const CALL_CONV_STDCALL: u16 = 0x0300;
    /// `thiscall`.
    pub const CALL_CONV_THISCALL: u16 = 0x0400;
    /// `fastcall`.
    pub const CALL_CONV_FASTCALL: u16 = 0x0500;
    /// The mask of the unmappable character behavior.
    pub const THROW_ON_UNMAPPABLE_CHAR_MASK: u16 = 0x3000;
    /// Throw on an unmappable character.
    pub const THROW_ON_UNMAPPABLE_CHAR_ENABLED: u16 = 0x1000;
    /// Do not throw on an unmappable character.
    pub const THROW_ON_UNMAPPABLE_CHAR_DISABLED: u16 = 0x2000;
}

/// The `ManifestResourceAttributes` (II.23.1.9).
pub mod manifest_resource_attributes {
    /// The mask of the visibility.
    pub const VISIBILITY_MASK: u32 = 0x0007;
    /// Exported.
    pub const PUBLIC: u32 = 0x0001;
    /// Not exported.
    pub const PRIVATE: u32 = 0x0002;
}

/// The `MethodAttributes` (II.23.1.10).
pub mod method_attributes {
    /// The mask of the accessibility.
    pub const MEMBER_ACCESS_MASK: u16 = 0x0007;
    /// Not referenceable.
    pub const COMPILER_CONTROLLED: u16 = 0x0000;
    /// Accessible only by the parent type.
    pub const PRIVATE: u16 = 0x0001;
    /// Accessible by subtypes in this assembly only.
    pub const FAM_AND_ASSEM: u16 = 0x0002;
    /// Accessible in this assembly.
    pub const ASSEM: u16 = 0x0003;
    /// Accessible by the type and its subtypes.
    pub const FAMILY: u16 = 0x0004;
    /// Accessible by subtypes and in this assembly.
    pub const FAM_OR_ASSEM: u16 = 0x0005;
    /// Accessible by all.
    pub const PUBLIC: u16 = 0x0006;
    /// A static method.
    pub const STATIC: u16 = 0x0010;
    /// The method cannot be overridden.
    pub const FINAL: u16 = 0x0020;
    /// A virtual method.
    pub const VIRTUAL: u16 = 0x0040;
    /// The method hides by name and signature.
    pub const HIDE_BY_SIG: u16 = 0x0080;
    /// The mask of the vtable layout.
    pub const VTABLE_LAYOUT_MASK: u16 = 0x0100;
    /// The method reuses a slot.
    pub const REUSE_SLOT: u16 = 0x0000;
    /// The method gets a new slot.
    pub const NEW_SLOT: u16 = 0x0100;
    /// Only an accessible method can override.
    pub const STRICT: u16 = 0x0200;
    /// An abstract method.
    pub const ABSTRACT: u16 = 0x0400;
    /// The name is special.
    pub const SPECIAL_NAME: u16 = 0x0800;
    /// A platform invoke method.
    pub const PINVOKE_IMPL: u16 = 0x2000;
    /// Reserved: an unmanaged export.
    pub const UNMANAGED_EXPORT: u16 = 0x0008;
    /// The runtime checks the name encoding.
    pub const RT_SPECIAL_NAME: u16 = 0x1000;
    /// The method has security attributes.
    pub const HAS_SECURITY: u16 = 0x4000;
    /// The method calls another method with security code.
    pub const REQUIRE_SEC_OBJECT: u16 = 0x8000;
}

/// The `MethodImplAttributes` (II.23.1.11).
pub mod method_impl_attributes {
    /// The mask of the code type.
    pub const CODE_TYPE_MASK: u16 = 0x0003;
    /// CIL code.
    pub const IL: u16 = 0x0000;
    /// Native code.
    pub const NATIVE: u16 = 0x0001;
    /// Reserved: optimized CIL.
    pub const OPTIL: u16 = 0x0002;
    /// The runtime provides the code.
    pub const RUNTIME: u16 = 0x0003;
    /// The mask of managed or unmanaged.
    pub const MANAGED_MASK: u16 = 0x0004;
    /// Unmanaged code.
    pub const UNMANAGED: u16 = 0x0004;
    /// Managed code.
    pub const MANAGED: u16 = 0x0000;
    /// The method is defined but has no body here.
    pub const FORWARD_REF: u16 = 0x0010;
    /// Reserved: keep the signature as declared.
    pub const PRESERVE_SIG: u16 = 0x0080;
    /// Reserved: an internal call.
    pub const INTERNAL_CALL: u16 = 0x1000;
    /// The method is single-threaded.
    pub const SYNCHRONIZED: u16 = 0x0020;
    /// The method must not be inlined.
    pub const NO_INLINING: u16 = 0x0008;
    /// The method must not be optimized.
    pub const NO_OPTIMIZATION: u16 = 0x0040;
    /// The method should be inlined (an extension of the .NET runtime).
    pub const AGGRESSIVE_INLINING: u16 = 0x0100;
    /// The method should be optimized at once (an extension of the .NET
    /// runtime).
    pub const AGGRESSIVE_OPTIMIZATION: u16 = 0x0200;
    /// The range check value.
    pub const MAX_METHOD_IMPL_VAL: u16 = 0xFFFF;
}

/// The `MethodSemanticsAttributes` (II.23.1.12).
pub mod method_semantics_attributes {
    /// A property setter.
    pub const SETTER: u16 = 0x0001;
    /// A property getter.
    pub const GETTER: u16 = 0x0002;
    /// Another method of a property or an event.
    pub const OTHER: u16 = 0x0004;
    /// The `add` method of an event.
    pub const ADD_ON: u16 = 0x0008;
    /// The `remove` method of an event.
    pub const REMOVE_ON: u16 = 0x0010;
    /// The `raise` method of an event.
    pub const FIRE: u16 = 0x0020;
}

/// The `ParamAttributes` (II.23.1.13).
pub mod param_attributes {
    /// An input parameter.
    pub const IN: u16 = 0x0001;
    /// An output parameter.
    pub const OUT: u16 = 0x0002;
    /// An optional parameter.
    pub const OPTIONAL: u16 = 0x0010;
    /// The parameter has a default value.
    pub const HAS_DEFAULT: u16 = 0x1000;
    /// The parameter has a marshalling descriptor.
    pub const HAS_FIELD_MARSHAL: u16 = 0x2000;
    /// The bits that are reserved.
    pub const UNUSED: u16 = 0xCFE0;
}

/// The `PropertyAttributes` (II.23.1.14).
pub mod property_attributes {
    /// The name is special.
    pub const SPECIAL_NAME: u16 = 0x0200;
    /// The runtime checks the name encoding.
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
    /// The property has a default value.
    pub const HAS_DEFAULT: u16 = 0x1000;
    /// The bits that are reserved.
    pub const UNUSED: u16 = 0xE9FF;
}

/// The `TypeAttributes` (II.23.1.15).
pub mod type_attributes {
    /// The mask of the visibility.
    pub const VISIBILITY_MASK: u32 = 0x0000_0007;
    /// Not visible outside the assembly.
    pub const NOT_PUBLIC: u32 = 0x0000_0000;
    /// Visible outside the assembly.
    pub const PUBLIC: u32 = 0x0000_0001;
    /// A nested type with public visibility.
    pub const NESTED_PUBLIC: u32 = 0x0000_0002;
    /// A nested type with private visibility.
    pub const NESTED_PRIVATE: u32 = 0x0000_0003;
    /// A nested type with family visibility.
    pub const NESTED_FAMILY: u32 = 0x0000_0004;
    /// A nested type with assembly visibility.
    pub const NESTED_ASSEMBLY: u32 = 0x0000_0005;
    /// A nested type with family and assembly visibility.
    pub const NESTED_FAM_AND_ASSEM: u32 = 0x0000_0006;
    /// A nested type with family or assembly visibility.
    pub const NESTED_FAM_OR_ASSEM: u32 = 0x0000_0007;
    /// The mask of the layout.
    pub const LAYOUT_MASK: u32 = 0x0000_0018;
    /// The runtime lays out the fields.
    pub const AUTO_LAYOUT: u32 = 0x0000_0000;
    /// The fields are in order.
    pub const SEQUENTIAL_LAYOUT: u32 = 0x0000_0008;
    /// The fields have explicit offsets.
    pub const EXPLICIT_LAYOUT: u32 = 0x0000_0010;
    /// The mask of the class semantics.
    pub const CLASS_SEMANTICS_MASK: u32 = 0x0000_0020;
    /// A class.
    pub const CLASS: u32 = 0x0000_0000;
    /// An interface.
    pub const INTERFACE: u32 = 0x0000_0020;
    /// An abstract type.
    pub const ABSTRACT: u32 = 0x0000_0080;
    /// A type that cannot have subtypes.
    pub const SEALED: u32 = 0x0000_0100;
    /// The name is special.
    pub const SPECIAL_NAME: u32 = 0x0000_0400;
    /// An imported type (COM).
    pub const IMPORT: u32 = 0x0000_1000;
    /// Reserved: a serializable type.
    pub const SERIALIZABLE: u32 = 0x0000_2000;
    /// A Windows Runtime type (an extension of the .NET runtime).
    pub const WINDOWS_RUNTIME: u32 = 0x0000_4000;
    /// The mask of the string format.
    pub const STRING_FORMAT_MASK: u32 = 0x0003_0000;
    /// ANSI strings.
    pub const ANSI_CLASS: u32 = 0x0000_0000;
    /// Unicode strings.
    pub const UNICODE_CLASS: u32 = 0x0001_0000;
    /// The platform chooses.
    pub const AUTO_CLASS: u32 = 0x0002_0000;
    /// A format of the implementation.
    pub const CUSTOM_FORMAT_CLASS: u32 = 0x0003_0000;
    /// The mask of the custom string format.
    pub const CUSTOM_STRING_FORMAT_MASK: u32 = 0x00C0_0000;
    /// The type initializer can run before the first static field access.
    pub const BEFORE_FIELD_INIT: u32 = 0x0010_0000;
    /// The runtime checks the name encoding.
    pub const RT_SPECIAL_NAME: u32 = 0x0000_0800;
    /// The type has security attributes.
    pub const HAS_SECURITY: u32 = 0x0004_0000;
    /// An exported type that forwards to another assembly.
    pub const IS_TYPE_FORWARDER: u32 = 0x0020_0000;
}
