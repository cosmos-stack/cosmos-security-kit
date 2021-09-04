using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;
// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyFNVExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifyFNV(this IValueRuleBuilder builder, string hexVal, FnvTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyFNV(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyFNV(this IValueRuleBuilder builder, string hexVal, FnvTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(FnvHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyFNV(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, FnvTypes type)
        {
            return builder.VerifyFNV(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyFNV(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, FnvTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(FnvHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyFNV<T>(this IValueRuleBuilder<T> builder, string hexVal, FnvTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyFNV<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyFNV<T>(this IValueRuleBuilder<T> builder, string hexVal, FnvTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(FnvHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyFNV<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, FnvTypes type)
        {
            return builder.VerifyFNV<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyFNV<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, FnvTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(FnvHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFNV<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, FnvTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyFNV<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFNV<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, FnvTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(FnvHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFNV<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, FnvTypes type)
        {
            return builder.VerifyFNV<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFNV<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, FnvTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(FnvHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}