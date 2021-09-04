using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyFarmHashExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifyFarmHash(this IValueRuleBuilder builder, string hexVal, FarmHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyFarmHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyFarmHash(this IValueRuleBuilder builder, string hexVal, FarmHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(FarmHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyFarmHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, FarmHashTypes type)
        {
            return builder.VerifyFarmHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyFarmHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, FarmHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(FarmHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyFarmHash<T>(this IValueRuleBuilder<T> builder, string hexVal, FarmHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyFarmHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyFarmHash<T>(this IValueRuleBuilder<T> builder, string hexVal, FarmHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(FarmHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyFarmHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, FarmHashTypes type)
        {
            return builder.VerifyFarmHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyFarmHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, FarmHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(FarmHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFarmHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, FarmHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyFarmHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFarmHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, FarmHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(FarmHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFarmHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, FarmHashTypes type)
        {
            return builder.VerifyFarmHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyFarmHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, FarmHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(FarmHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}