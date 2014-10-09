namespace Impersonator.Test {
    using System.Security.Principal;

    using CredentialManagement;

    using FluentAssertions;

    using Xunit;

    public class ImpersonatorManualTests {
        [Fact]
        public void GivenTesterContext_WhenImpersonating_ThenUsersNotEqual() {
            // arrange
            var currentUser = string.Empty;
            var impersonatedUser = string.Empty;

            using (var windowsIdentity = WindowsIdentity.GetCurrent()) {
                currentUser = windowsIdentity.Name;
            }

            var credential = new Credential { Target = "ImpersonatorManualTest" };
            var loadResult = credential.Load();
            loadResult.Should()
                .BeTrue(
                    "because a credential entry in Windows Credential Manager was not found for target [{0}]",
                    credential.Target);

            var userNameSplit = credential.Username.Split('\\');
            var domain = userNameSplit[0];
            var username = userNameSplit[1];


            // act
            using (new Impersonator(username, domain, credential.Password)) {
                using (var windowsIdentity = WindowsIdentity.GetCurrent()) {
                    if (windowsIdentity != null) {
                        impersonatedUser = windowsIdentity.Name;
                    }
                }
            }

            // assert
            currentUser.Should().NotBeNullOrWhiteSpace();
            impersonatedUser.Should().NotBeNullOrWhiteSpace();
            impersonatedUser.Should().NotBe(currentUser);
        }
    }
}