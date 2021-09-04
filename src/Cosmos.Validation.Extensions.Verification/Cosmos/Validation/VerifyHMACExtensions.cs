using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyHMACExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifyHMAC(this IValueRuleBuilder builder, string hexVal, HmacTypes type, string key, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyHMAC(hexVal, type, key, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyHMAC(this IValueRuleBuilder builder, string hexVal, HmacTypes type, string key, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(HmacHandler.Verify()(hexVal)(type)(key)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyHMAC(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, HmacTypes type, string key)
        {
            return builder.VerifyHMAC(checker, type, key, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyHMAC(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, HmacTypes type, string key, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(HmacHandler.CustomVerify()(type)(key)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyHMAC<T>(this IValueRuleBuilder<T> builder, string hexVal, HmacTypes type, string key, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyHMAC<T>(hexVal, type, key, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyHMAC<T>(this IValueRuleBuilder<T> builder, string hexVal, HmacTypes type, string key, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(HmacHandler.Verify()(hexVal)(type)(key)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyHMAC<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, HmacTypes type, string key)
        {
            return builder.VerifyHMAC<T>(checker, type, key, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyHMAC<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, HmacTypes type, string key, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(HmacHandler.CustomVerify()(type)(key)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyHMAC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, HmacTypes type, string key, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyHMAC<T, TVal>(hexVal, type, key, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyHMAC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, HmacTypes type, string key, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(HmacHandler.Verify<TVal>()(hexVal)(type)(key)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyHMAC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, HmacTypes type, string key)
        {
            return builder.VerifyHMAC<T, TVal>(checker, type, key, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyHMAC<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, HmacTypes type, string key, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(HmacHandler.CustomVerify<TVal>()(type)(key)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}